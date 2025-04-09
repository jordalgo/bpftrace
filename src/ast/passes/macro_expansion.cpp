#include <unordered_map>
#include <unordered_set>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/macro_expansion.h"
#include "ast/visitor.h"
#include "bpftrace.h"

#include "log.h"

namespace bpftrace::ast {

// Specialies a macro body for its call site.
class MacroSpecializer : public Visitor<MacroSpecializer> {
public:
  MacroSpecializer(ASTContext &ast, const std::string &macro_name);

  using Visitor<MacroSpecializer>::visit;
  void visit(VarDeclStatement &statement);
  void visit(Map &map);
  
  using Visitor<MacroSpecializer>::replace;
  AssignVarStatement *replace(AssignVarStatement* assignment, void *ret);
  Variable *replace(Variable *var, void *ret);
  Binop *replace(Binop *binop, void *ret);

  Expression *specialize(Macro &macro, const Call &call);

private:
  ASTContext &ast_;
  std::string macro_name_;
  
  std::string make_var_literal_ident(std::string original_ident);

  // Maps of macro map/var names -> callsite map/var names
  std::unordered_map<std::string, std::string> maps_;
  std::unordered_map<std::string, std::string> vars_;
  std::unordered_map<std::string, std::string> literals_;
};

// Expands macros into their call sites.
class MacroExpansion : public Visitor<MacroExpansion> {
public:
  MacroExpansion(ASTContext &ast, BPFtrace &b);

  using Visitor<MacroExpansion>::replace;
  Expression *replace(Call *call, void *ret);

  void run();

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  std::unordered_map<std::string, Macro *> macros_;
  std::unordered_set<std::string> called_;
};

MacroSpecializer::MacroSpecializer(ASTContext &ast, const std::string &macro_name) : ast_(ast), macro_name_(macro_name) {}

void MacroSpecializer::visit(VarDeclStatement &statement)
{
  std::string ident = statement.var->ident;
  vars_[ident] = ident;

  Visitor<MacroSpecializer>::visit(statement);
}

AssignVarStatement *MacroSpecializer::replace(AssignVarStatement* assignment, [[maybe_unused]] void *ret)
{
  std::cout << "assignvar \n";
  return ast_.make_node<AssignVarStatement>(replace(assignment->var, nullptr), replace(assignment->expr, nullptr), Location(assignment->loc));
}

Variable *MacroSpecializer::replace(Variable *var, [[maybe_unused]] void *ret)
{
  std::cout << "variable \n";
  if (auto it = vars_.find(var->ident); it != vars_.end()) {
    return ast_.make_node<Variable>(it->second, Location(var->loc));
  } else if (auto it = literals_.find(var->ident); it != literals_.end()) {
    return ast_.make_node<Variable>(make_var_literal_ident(var->ident), Location(var->loc));
  }
  return var;
}

Binop *MacroSpecializer::replace(Binop *binop, [[maybe_unused]] void *ret)
{
  std::cout << "binop \n";
  return ast_.make_node<Binop>(replace(binop->left, nullptr), binop->op, replace(binop->right, nullptr), Location(binop->loc));
}

// void MacroSpecializer::visit(Variable &var)
// {
//   if (auto it = vars_.find(var.ident); it != vars_.end()) {
//     var.ident = it->second;
//   } else if (auto it = literals_.find(var.ident); it == literals_.end()) {
//     var.addError() << "Unhygienic access to variable";
//   }
// }

void MacroSpecializer::visit(Map &map)
{
  if (auto it = maps_.find(map.ident); it != maps_.end()) {
    map.ident = it->second;
  } else {
    map.addError() << "Unhygienic access to map";
  }
}

std::string MacroSpecializer::make_var_literal_ident(std::string original_ident) {
  return "$$" + macro_name_ + "_" + original_ident;
}

Expression *MacroSpecializer::specialize(Macro &macro, const Call &call)
{
  maps_.clear();
  vars_.clear();

  if (macro.args.size() != call.vargs.size()) {
    call.addError() << "Call to macro has wrong number arguments: "
                    << macro.args.size() << "!=" << call.vargs.size();
    return nullptr;
  }
  
  StatementList stmt_list;

  for (size_t i = 0; i < call.vargs.size(); i++) {
    Expression *marg = macro.args[i];
    Expression *carg = call.vargs[i];

    if (auto *cvar = dynamic_cast<Variable *>(carg)) {
      if (auto *mvar = dynamic_cast<Variable *>(marg)) {
        vars_[mvar->ident] = cvar->ident;
      } else {
        call.addError() << "Mismatched arg=" << i << " to macro call";
      }
    } else if (auto *cmap = dynamic_cast<Map *>(carg)) {
      if (auto *mmap = dynamic_cast<Map *>(marg)) {
        maps_[mmap->ident] = cmap->ident;
      } else {
        call.addError() << "Mismatched arg=" << i << " to macro call";
      }
    } else if (carg->is_literal) {
      if (auto *mvar = dynamic_cast<Variable *>(marg)) {
        auto literal_ident = make_var_literal_ident(mvar->ident);
        literals_[mvar->ident] = literal_ident;
        stmt_list.push_back(ast_.make_node<AssignVarStatement>(ast_.make_node<Variable>(literal_ident, Location(call.loc)), carg, Location(call.loc)));
      } else if (dynamic_cast<Map *>(marg) != nullptr) {
        call.addError() << "Trying to pass a literal when macro expects a map argument";
      }
    } else {
      call.addError() << "Arguments to macros must be variables, maps, or literals.";
    }
  }
  
  for (const auto expr : macro.expr->stmts) {
    stmt_list.push_back(replace(expr, nullptr));
  }
  
  auto cloned_block = ast_.make_node<Block>(std::move(stmt_list), replace(macro.expr->expr, nullptr), Location(macro.loc));

  // TODO: clone the macro body
  visit(cloned_block);

  return ast_.diagnostics().ok() ? cloned_block : nullptr;
}

MacroExpansion::MacroExpansion(ASTContext &ast, BPFtrace &b)
    : ast_(ast), bpftrace_(b)
{
}

void MacroExpansion::run()
{
  bool unstable_macro = bpftrace_.config_->get(ConfigKeyBool::unstable_macro);

  for (Macro *macro : ast_.root->macros) {
    if (!unstable_macro) {
      macro->addError()
          << "Hygienic macros are not enabled by default. To enable "
             "this unstable feature, set this config flag to 1 "
             "e.g. unstable_macro=1";
      return;
    }

    macros_[macro->name] = macro;
  }

  visit(ast_.root);
}

Expression *MacroExpansion::replace(Call *call, [[maybe_unused]] void *ret)
{
  if (auto it = macros_.find(call->func); it != macros_.end()) {
    // bool has_bad_args = false;
    // for (size_t i = 0; i < call->vargs.size(); ++i) {
    //   auto *expr = call->vargs[i];
    //   if (dynamic_cast<Map *>(expr) == nullptr && dynamic_cast<Variable *>(expr) == nullptr) {
    //     call->addError() << "Arguments to macros must be variables or maps.";
    //     has_bad_args = true;
    //   }
    // }
    
    // if (has_bad_args)
    //   return nullptr;
    
    // if (called_.contains(call->func)) {
    //   call->addError() << "The PoC can only handle a single call of: "
    //                    << call->func;
    //   return nullptr;
    // } else {
    //   called_.insert(call->func);
    // }

    Macro *macro = it->second;
    Expression *expr = MacroSpecializer(ast_, macro->name).specialize(*macro, *call);
    if (expr) {
      return expr;
    } else {
      call->addError() << "Failed to specialize macro: " << call->func;
      return call;
    }
  }

  return call;
}

Pass CreateMacroExpansionPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    MacroExpansion expander(ast, b);
    expander.run();
  };

  return Pass::create("MacroExpansion", fn);
}

} // namespace bpftrace::ast
