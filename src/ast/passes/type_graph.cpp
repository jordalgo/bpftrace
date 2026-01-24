#include "ast/passes/type_graph.h"
#include "ast/ast.h"
#include "ast/passes/fold_literals.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"

#include <functional>

namespace bpftrace::ast {

namespace {

template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};

using ScopedVariable = std::pair<Node *, std::string>;
using GraphNode = std::variant<Node *, Typeof *, ScopedVariable, std::string>;
using ConcreteTypes = std::pair<GraphNode, SizedType>;

struct ScopedVariableHash {
  std::size_t operator()(const ScopedVariable &sv) const
  {
    auto h1 = std::hash<Node *>{}(sv.first);
    auto h2 = std::hash<std::string>{}(sv.second);
    return h1 ^ (h2 << 1);
  }
};

struct GraphNodeHash {
  std::size_t operator()(const GraphNode &gn) const
  {
    return std::visit(
        [](const auto &val) -> std::size_t {
          using T = std::decay_t<decltype(val)>;
          if constexpr (std::is_same_v<T, Node *>) {
            return std::hash<Node *>{}(val);
          } else if constexpr (std::is_same_v<T, Typeof *>) {
            return std::hash<Typeof *>{}(val);
          } else if constexpr (std::is_same_v<T, std::string>) {
            return std::hash<std::string>{}(val);
          } else {
            return ScopedVariableHash{}(val);
          }
        },
        gn);
  }
};

using LockedVariables =
    std::unordered_map<ScopedVariable, SizedType, ScopedVariableHash>;

struct TypeSources {
  std::vector<GraphNode> nodes;
  std::vector<SizedType> resolved_types;
  uint64_t num_resolved = 0;
  std::function<std::optional<SizedType>(const GraphNode &,
                                         std::vector<SizedType>)>
      callback = [](const GraphNode &graph_node,
                    std::vector<SizedType>) -> std::optional<SizedType> {
    // Default callback: for Typeof nodes, return their type directly.
    // For other nodes, propagate the source type.
    if (auto *const *typeof_ptr = std::get_if<Typeof *>(&graph_node)) {
      return (*typeof_ptr)->type();
    }
    LOG(BUG)
        << "Implementation of the TypeSources callback needed for non Typeof";
    return std::nullopt;
  };
};

class TypeGraphPass : public Visitor<TypeGraphPass> {
public:
  explicit TypeGraphPass(ASTContext &ast,
                         BPFtrace &bpftrace,
                         LockedVariables locked_variables = {})
      : ast_(ast),
        bpftrace_(bpftrace),
        locked_variables_(std::move(locked_variables))
  {
    // N.B. we can't just pre-populate the variables_ map with locked_variables
    // because we rely on certain insert ordering into the variables_ map to
    // determine if there is variable shadowing or repeated declarations.
  }

  using Visitor<TypeGraphPass>::visit;
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(Binop &binop);
  void visit(BlockExpr &block);
  void visit(Boolean &boolean);
  void visit(Cast &cast);
  void visit(Comptime &comptime);
  void visit(Expression &expr);
  void visit(ExprStatement &expr);
  void visit(IfExpr &if_expr);
  void visit(Integer &integer);
  void visit(Map &map);
  void visit(MapAccess &acc);
  void visit(NegativeInteger &integer);
  void visit(String &string);
  void visit(Typeof &typeof);
  void visit(Typeinfo &typeinfo);
  void visit(Variable &var);
  void visit(VarDeclStatement &decl);

  bool resolve();
  LockedVariables get_locked_variables();

  const std::vector<Comptime *> &get_unresolved_comptimes() const
  {
    return unresolved_comptimes_;
  }

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  const LockedVariables locked_variables_;
  // Concrete Types (like literals) are kept out of the source/consumer graph
  // primarily to maintain AST visiting order and to reduce the size of these
  // maps as they have no sources that provide them with types
  std::vector<ConcreteTypes> concrete_types_;
  std::unordered_map<GraphNode, std::vector<GraphNode>, GraphNodeHash>
      source_to_consumers_;
  std::unordered_map<GraphNode, TypeSources, GraphNodeHash>
      consumer_to_sources_;
  std::unordered_map<Node *, std::unordered_map<std::string, SizedType>>
      variables_;
  std::unordered_map<std::string, std::pair<SizedType, SizedType>> maps_;
  // At the moment we iterate over the stack from top to
  // bottom as variable shadowing is not supported.
  std::vector<Node *> scope_stack_;
  int introspection_level_ = 0;
  std::unordered_set<ScopedVariable, ScopedVariableHash>
      introspected_variables_;

  std::vector<Comptime *> unresolved_comptimes_;

  void propagate_resolved_type(const GraphNode &graph_node,
                               const SizedType &type);
  Node *find_variable_scope(const std::string &var_ident, bool safe = false);
  std::string get_map_value_name(const std::string &ident);
  std::string get_map_key_name(const std::string &ident);
};

std::optional<SizedType> get_promoted_int(const SizedType &leftTy,
                                          const SizedType &rightTy)
{
  bool leftSigned = leftTy.IsSigned();
  bool rightSigned = rightTy.IsSigned();
  auto leftSize = leftTy.GetSize();
  auto rightSize = rightTy.GetSize();

  if (leftSigned != rightSigned) {
    if (leftSigned) {
      if (leftSize > rightSize) {
        return leftTy;
      }
    } else if (rightSigned) {
      if (rightSize > leftSize) {
        return rightTy;
      }
    }

    size_t new_size = std::max(leftSize, rightSize) * 2;
    if (new_size > 8) {
      return std::nullopt;
    } else {
      return CreateInteger(new_size * 8, true);
    }
  }

  // Same sign - return the larger of the two
  size_t new_size = std::max(leftSize, rightSize);
  return CreateInteger(new_size * 8, leftSigned);
}

// Unifies multiple source types into a single final type by finding
// the common compatible type (promoting integers, taking larger strings, etc.)
SizedType unify_map_types(const std::vector<SizedType> &sources)
{
  SizedType final_type;
  bool first = true;

  for (const auto &type : sources) {
    if (first) {
      final_type = type;
      first = false;
      continue;
    }

    if (final_type == type || !final_type.IsCompatible(type)) {
      continue;
    }

    if (final_type.IsIntegerTy()) {
      auto promoted_type = get_promoted_int(type, final_type);
      if (!promoted_type) {
        LOG(BUG) << "Couldn't promote type, this should have "
                    "been caught by IsCompatible";
      }

      final_type = *promoted_type;
    } else if (final_type.IsStringTy()) {
      if (type.GetSize() > final_type.GetSize()) {
        final_type = type;
      }
    }
  }

  return final_type;
}

} // namespace

void TypeGraphPass::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);

  auto value_name = get_map_value_name(assignment.map_access->map->ident);
  source_to_consumers_[&assignment.expr.node()].emplace_back(value_name);
  consumer_to_sources_[value_name].nodes.emplace_back(&assignment.expr.node());
  consumer_to_sources_[value_name].callback =
      [this, &assignment](const GraphNode &, std::vector<SizedType> sources)
      -> std::optional<SizedType> {
    SizedType final_type = unify_map_types(sources);
    maps_[assignment.map_access->map->ident].second = final_type;
    return final_type;
  };
}

void TypeGraphPass::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);
  visit(assignment.var_decl);

  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    auto *var_decl = std::get<VarDeclStatement *>(assignment.var_decl);
    if (var_decl->typeof) {
      // The type of this variable is determined by the typeof, not the r-value.
      return;
    }
  }

  Node *var_scope = find_variable_scope(assignment.var()->ident);
  ScopedVariable scoped_var = std::make_pair(var_scope,
                                             assignment.var()->ident);

  source_to_consumers_[&assignment.expr.node()].emplace_back(scoped_var);

  consumer_to_sources_[scoped_var].nodes.emplace_back(&assignment.expr.node());

  // We only need to create this callback once
  if (consumer_to_sources_[scoped_var].nodes.size() == 1) {
    consumer_to_sources_[scoped_var].callback =
        [this, scoped_var, &assignment](
            const GraphNode &,
            std::vector<SizedType> sources) -> std::optional<SizedType> {
      Node *scope = scoped_var.first;
      const auto &var = scoped_var.second;
      auto foundVar = variables_[scope].find(var);

      if (foundVar == variables_[scope].end()) {
        LOG(BUG) << "Variable " << var << " should exist in the variables_ map";
      }

      if (auto found_locked = locked_variables_.find(scoped_var);
          found_locked != locked_variables_.end()) {
        foundVar->second = found_locked->second;
        return found_locked->second;
      }

      SizedType final_type;
      bool first = true;

      for (const auto &type : sources) {
        if (first) {
          final_type = type;
          first = false;
          continue;
        }

        if (final_type == type || !final_type.IsCompatible(type)) {
          continue;
        }

        if (final_type.IsIntegerTy()) {
          auto promoted_type = get_promoted_int(type, final_type);
          if (!promoted_type) {
            LOG(BUG) << "Couldn't promote type, this should have "
                        "been caught by IsCompatible";
          }

          final_type = *promoted_type;
        } else if (final_type.IsStringTy()) {
          if (type.GetSize() > final_type.GetSize()) {
            final_type = type;
          }
        }
      }

      foundVar->second = final_type;

      return final_type;
    };
  }
}

void TypeGraphPass::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  if (is_comparison_op(op.op)) {
    op.result_type = CreateBool();
    concrete_types_.emplace_back(&op, op.result_type);
    return;
  }

  source_to_consumers_[&op.left.node()].emplace_back(&op);
  source_to_consumers_[&op.right.node()].emplace_back(&op);

  consumer_to_sources_[&op].nodes.emplace_back(&op.left.node());
  consumer_to_sources_[&op].nodes.emplace_back(&op.right.node());

  consumer_to_sources_[&op].callback =
      [this, &op](const GraphNode &,
                  std::vector<SizedType> sources) -> std::optional<SizedType> {
    if (sources.size() != 2) {
      LOG(BUG) << "Should only have 2 binop sources";
    }
    SizedType left_type = sources.front();
    SizedType right_type = sources.back();

    // Never resolve this type if there is a mismatch
    if (left_type == right_type) {
      // We'll handle casting later
      op.result_type = left_type;
    } else if (left_type.IsCompatible(right_type)) {
      if (left_type.IsIntegerTy()) {
        auto promoted_type = get_promoted_int(left_type, right_type);
        if (!promoted_type) {
          LOG(BUG) << "Couldn't promote type, this should have "
                      "been caught by IsCompatible";
        }

        op.result_type = *promoted_type;
      } else if (left_type.IsStringTy()) {
        if (left_type.GetSize() > right_type.GetSize()) {
          op.result_type = left_type;
        } else {
          op.result_type = right_type;
        }
      }
    } else {
      return std::nullopt;
    }

    return op.result_type;
  };
}

void TypeGraphPass::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  visit(block.stmts);
  visit(block.expr);

  source_to_consumers_[&block.expr.node()].emplace_back(&block);
  consumer_to_sources_[&block].nodes.emplace_back(&block.expr.node());

  consumer_to_sources_[&block].callback =
      [](const GraphNode &,
         std::vector<SizedType> sources) -> std::optional<SizedType> {
    if (sources.size() != 1) {
      LOG(BUG) << "Block expr should have only one source";
    }
    return sources.back();
  };

  scope_stack_.pop_back();
}

void TypeGraphPass::visit(Boolean &boolean)
{
  concrete_types_.emplace_back(&boolean, boolean.type());
}

void TypeGraphPass::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);

  source_to_consumers_[cast.typeof].emplace_back(&cast);
  consumer_to_sources_[&cast].nodes.emplace_back(cast.typeof);
  consumer_to_sources_[&cast].callback =
      [](const GraphNode &,
         std::vector<SizedType> sources) -> std::optional<SizedType> {
    if (sources.size() != 1) {
      LOG(BUG) << "Cast expr should have only one source";
    }
    return sources.back();
  };
}

void TypeGraphPass::visit(Comptime &comptime)
{
  visit(comptime.expr);
  unresolved_comptimes_.emplace_back(&comptime);
}

void TypeGraphPass::visit(Expression &expr)
{
  Visitor<TypeGraphPass>::visit(expr);

  if (auto *typeinfo = expr.as<Typeinfo>()) {
    source_to_consumers_[typeinfo->typeof].emplace_back(typeinfo);
    consumer_to_sources_[typeinfo].nodes.emplace_back(typeinfo->typeof);
    consumer_to_sources_[typeinfo].callback =
        [this,
         &expr,
         typeinfo](const GraphNode &,
                   std::vector<SizedType> sources) -> std::optional<SizedType> {
      if (sources.size() != 1) {
        LOG(BUG) << "Typeinfo should have only one source";
      }

      SizedType type = sources.back();

      // We currently lack a globally-unique enumeration of types. For
      // simplicity, just use the type string with a placeholder identifier.
      auto *id = ast_.make_node<Integer>(typeinfo->loc, 0);
      auto *base_ty = ast_.make_node<String>(typeinfo->loc,
                                             to_string(type.GetTy()));
      auto *full_ty = ast_.make_node<String>(typeinfo->loc, typestr(type));
      auto *typeinfo_tuple = ast_.make_node<Tuple>(
          typeinfo->loc, ExpressionList{ id, base_ty, full_ty });
      std::vector<SizedType> elements = { id->type(),
                                          base_ty->type(),
                                          full_ty->type() };
      typeinfo_tuple->tuple_type = CreateTuple(Struct::CreateTuple(elements));

      expr.value = typeinfo_tuple;

      return typeinfo_tuple->tuple_type;
    };
  }
}

void TypeGraphPass::visit(ExprStatement &expr)
{
  visit(expr.expr);
}

void TypeGraphPass::visit(IfExpr &if_expr)
{
  if (auto *comptime = if_expr.cond.as<Comptime>()) {
    visit(comptime->expr);
    unresolved_comptimes_.emplace_back(comptime);
    return; // Skip visiting this `if` for now.
  }

  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);
}

void TypeGraphPass::visit(Integer &integer)
{
  concrete_types_.emplace_back(&integer, integer.type());
}

void TypeGraphPass::visit(Map &map)
{
  maps_.insert({ map.ident, std::make_pair(CreateNone(), CreateNone()) });

  auto key_name = get_map_key_name(map.ident);
  auto value_name = get_map_value_name(map.ident);
  source_to_consumers_[key_name].emplace_back(&map);
  source_to_consumers_[value_name].emplace_back(&map);

  consumer_to_sources_[&map].nodes.emplace_back(key_name);
  consumer_to_sources_[&map].nodes.emplace_back(value_name);
  consumer_to_sources_[&map].callback =
      [&map](const GraphNode &,
             std::vector<SizedType> sources) -> std::optional<SizedType> {
    if (sources.size() != 2) {
      LOG(BUG) << "Map should have two sources";
    }
    map.key_type = sources.front();
    map.value_type = sources.back();

    return map.value_type;
  };

  // if (introspection_level_ > 0) {
  //   introspected_variables_.insert(map);
  // }
}

void TypeGraphPass::visit(MapAccess &acc)
{
  visit(acc.map);
  visit(acc.key);

  auto key_name = get_map_key_name(acc.map->ident);

  source_to_consumers_[&acc.key.node()].emplace_back(key_name);
  consumer_to_sources_[key_name].nodes.emplace_back(&acc.key.node());
  consumer_to_sources_[key_name].callback =
      [this, &acc](const GraphNode &,
                   std::vector<SizedType> sources) -> std::optional<SizedType> {
    SizedType final_type = unify_map_types(sources);
    maps_[acc.map->ident].first = final_type;
    return final_type;
  };

  auto value_name = get_map_value_name(acc.map->ident);
  source_to_consumers_[value_name].emplace_back(&acc);
  consumer_to_sources_[&acc].nodes.emplace_back(value_name);
  consumer_to_sources_[&acc].callback =
      [](const GraphNode &,
         std::vector<SizedType> sources) -> std::optional<SizedType> {
    if (sources.size() != 1) {
      LOG(BUG) << "MapAccess should have one source";
    }
    return sources.back();
  };
}

void TypeGraphPass::visit(NegativeInteger &integer)
{
  concrete_types_.emplace_back(&integer, integer.type());
}

void TypeGraphPass::visit(String &str)
{
  concrete_types_.emplace_back(&str, str.type());
}

void TypeGraphPass::visit(Typeof &typeof)
{
  if (std::holds_alternative<SizedType>(typeof.record)) {
    concrete_types_.emplace_back(&typeof, std::get<SizedType>(typeof.record));
  } else {
    auto &expr = std::get<Expression>(typeof.record);
    visit(expr);

    source_to_consumers_[&expr.node()].emplace_back(&typeof);
    consumer_to_sources_[&typeof].nodes.emplace_back(&expr.node());

    // if (auto *ident = expr.as<Identifier>()) {
    //   auto stype = bpftrace_.btf_->get_stype(ident->ident);
    //   if (!stype.IsNoneTy()) {
    //     typeof_node.record = stype;
    //   }
    // }
  }
}

void TypeGraphPass::visit(Typeinfo &typeinfo)
{
  ++introspection_level_;
  visit(typeinfo.typeof);
  --introspection_level_;
}

void TypeGraphPass::visit(Variable &var)
{
  Node *scope = find_variable_scope(var.ident);
  if (scope == nullptr) {
    scope = scope_stack_.back();
  }
  variables_[scope].insert({ var.ident, CreateNone() });

  ScopedVariable scoped_var = std::make_pair(scope, var.ident);

  source_to_consumers_[scoped_var].emplace_back(&var);

  consumer_to_sources_[&var].nodes.emplace_back(scoped_var);
  consumer_to_sources_[&var].callback =
      [&var](const GraphNode &,
             std::vector<SizedType> sources) -> std::optional<SizedType> {
    if (sources.size() != 1) {
      LOG(BUG) << "Variable should have only one source";
    }
    var.var_type = sources.back();
    return var.var_type;
  };

  if (introspection_level_ > 0) {
    introspected_variables_.insert(scoped_var);
  }
}

void TypeGraphPass::visit(VarDeclStatement &decl)
{
  Node *scope = find_variable_scope(decl.var->ident);
  if (scope == nullptr) {
    scope = scope_stack_.back();
  } else {
    decl.addError() << "No variable shadowing";
  }
  if (!decl.typeof) {
    visit(decl.var);
    return;
  }

  visit(decl.typeof);

  ScopedVariable scoped_var = std::make_pair(scope, decl.var->ident);

  source_to_consumers_[decl.typeof].emplace_back(scoped_var);
  consumer_to_sources_[scoped_var].nodes.emplace_back(decl.typeof);
  consumer_to_sources_[scoped_var].callback =
      [this,
       scoped_var](const GraphNode &,
                   std::vector<SizedType> sources) -> std::optional<SizedType> {
    if (sources.size() != 1) {
      LOG(BUG) << "Var decl typeof should have only one source";
    }
    Node *scope = scoped_var.first;
    const auto &var = scoped_var.second;
    auto foundVar = variables_[scope].find(var);

    if (foundVar == variables_[scope].end()) {
      LOG(BUG) << "Variable " << var << " should exist in the variables_ map";
    }

    foundVar->second = sources.back();

    return foundVar->second;
  };

  visit(decl.var);
}

void TypeGraphPass::propagate_resolved_type(const GraphNode &graph_node,
                                            const SizedType &type)
{
  if (auto found = source_to_consumers_.find(graph_node);
      found != source_to_consumers_.end()) {
    for (const auto &consumer : found->second) {
      auto &sources = consumer_to_sources_[consumer];
      if (sources.resolved_types.size() == 0) {
        sources.resolved_types.resize(sources.nodes.size());
      }
      auto it = std::find(sources.nodes.begin(),
                          sources.nodes.end(),
                          graph_node);
      // The indexes of the resolved types should match the indexes of the nodes
      // that supplied them
      if (it == sources.nodes.end()) {
        LOG(BUG) << "Graph node not in sources nodes";
      } else {
        auto index = std::distance(sources.nodes.begin(), it);
        sources.resolved_types[index] = type;
        ++sources.num_resolved;
      }
    }
  }
}

bool TypeGraphPass::resolve()
{
  for (const auto &concrete_type : concrete_types_) {
    propagate_resolved_type(concrete_type.first, concrete_type.second);
  }

  bool made_progress = true;
  while (made_progress) {
    made_progress = false;
    for (auto it = consumer_to_sources_.begin();
         it != consumer_to_sources_.end();) {
      auto &sources = it->second;
      if (sources.nodes.size() != sources.num_resolved) {
        ++it;
        continue;
      }

      made_progress = true;
      auto resolved_type = sources.callback(it->first, sources.resolved_types);
      auto consumer = it->first;
      it = consumer_to_sources_.erase(it);

      if (resolved_type) {
        propagate_resolved_type(consumer, *resolved_type);
      }
    }
  }

  if (!ast_.diagnostics().ok()) {
    return false;
  }

  fold(ast_);

  return true;
}

LockedVariables TypeGraphPass::get_locked_variables()
{
  LockedVariables locked_vars;
  for (auto &scoped_var : introspected_variables_) {
    if (auto search_val = variables_[scoped_var.first].find(scoped_var.second);
        search_val != variables_[scoped_var.first].end()) {
      if (!search_val->second.IsNoneTy()) {
        locked_vars.insert({ std::move(scoped_var), search_val->second });
      }
    }
  }
  return locked_vars;
}

Node *TypeGraphPass::find_variable_scope(const std::string &var_ident,
                                         bool safe)
{
  for (auto *scope : scope_stack_) {
    if (auto search_val = variables_[scope].find(var_ident);
        search_val != variables_[scope].end()) {
      return scope;
    }
  }
  if (safe) {
    LOG(BUG) << "No scope found for variable: " << var_ident;
  }
  return nullptr;
}

std::string TypeGraphPass::get_map_value_name(const std::string &ident)
{
  return ident + "__val";
}

std::string TypeGraphPass::get_map_key_name(const std::string &ident)
{
  return ident + "__key";
}

Pass CreateTypeGraphPass()
{
  return Pass::create("TypeGraph", [](ASTContext &ast, BPFtrace &b) {
    auto type_graph = TypeGraphPass(ast, b);
    type_graph.visit(ast.root);
    type_graph.resolve();

    auto prev_comptimes = type_graph.get_unresolved_comptimes();
    LockedVariables locked_vars = type_graph.get_locked_variables();

    while (prev_comptimes.size() > 0) {
      auto next_pass = TypeGraphPass(ast, b, locked_vars);
      next_pass.visit(ast.root);
      next_pass.resolve();

      auto next_comptimes = next_pass.get_unresolved_comptimes();
      if (prev_comptimes == next_comptimes) {
        for (auto *comptime : next_comptimes) {
          comptime->addError() << "Unable to resolve comptime expression";
        }
        break;
      }
      prev_comptimes = next_comptimes;
      locked_vars = next_pass.get_locked_variables();
    }
  });
};

} // namespace bpftrace::ast
