#include "ast/passes/cast_creator.h"
#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"

#include <functional>

namespace bpftrace::ast {

namespace {

class CastCreatorPass : public Visitor<CastCreatorPass> {
public:
  explicit CastCreatorPass(ASTContext &ast, BPFtrace &bpftrace)
      : ctx_(ast), bpftrace_(bpftrace)
  {
  }

  using Visitor<CastCreatorPass>::visit;
  void visit(AssignVarStatement &assignment);
  void visit(Binop &binop);
  void visit(BlockExpr &block);
  void visit(Cast &cast);
  void visit(IfExpr &if_expr);
  void visit(Variable &var);

private:
  ASTContext &ctx_;
  BPFtrace &bpftrace_;
};

} // namespace

void CastCreatorPass::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);
  visit(assignment.var_decl);

  const auto &expr_type = assignment.expr.type();
  const auto &var_type = assignment.var()->type();

  if (var_type == expr_type) {
    return;
  }

  if (expr_type.FitsInto(var_type)) {
    if (auto *integer = assignment.expr.as<Integer>()) {
      assignment.expr = ctx_.make_node<Integer>(Location(assignment.expr.loc()),
                                                integer->value,
                                                var_type,
                                                integer->original);
    } else {
      auto *typeof = ctx_.make_node<Typeof>(assignment.expr.loc(), var_type);
      assignment.expr = ctx_.make_node<Cast>(
          Location(assignment.expr.loc()),
          typeof,
          clone(ctx_, assignment.expr.loc(), assignment.expr));
    }
    return;
  }

  assignment.addError() << "Type mismatch for " << assignment.var()->ident
                        << ": "
                        << "trying to assign value of type '" << expr_type
                        << "' when variable already has a type '" << var_type
                        << "'";
}

void CastCreatorPass::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  if (is_comparison_op(op.op)) {
    return;
  }
}

void CastCreatorPass::visit(BlockExpr &block)
{
  visit(block.stmts);
  visit(block.expr);
}

void CastCreatorPass::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);
}

void CastCreatorPass::visit(IfExpr &if_expr)
{
  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);
}

void CastCreatorPass::visit(Variable &var)
{
  if (var.var_type.IsNoneTy()) {
    var.addError() << "Could not resolve the type of this variable";
  }
}

Pass CreateCastCreatorPass()
{
  return Pass::create("CastCreator", [](ASTContext &ast, BPFtrace &b) {
    auto type_graph = CastCreatorPass(ast, b);
    type_graph.visit(ast.root);
  });
};

} // namespace bpftrace::ast
