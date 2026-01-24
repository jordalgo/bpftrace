#include "ast/passes/cast_creator.h"
#include "ast/ast.h"
#include "bpftrace.h"
#include "log.h"

#include <functional>

namespace bpftrace::ast {

CastCreator::CastCreator(ASTContext &ast, BPFtrace &bpftrace)
    : ctx_(ast), bpftrace_(bpftrace)
{
}

void CastCreator::visit(AssignVarStatement &assignment)
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

void CastCreator::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  if (is_comparison_op(op.op)) {
    return;
  }
}

void CastCreator::visit(BlockExpr &block)
{
  visit(block.stmts);
  visit(block.expr);
}

void CastCreator::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);
}

void CastCreator::visit(IfExpr &if_expr)
{
  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);
}

void CastCreator::visit(Variable &var)
{
  if (var.var_type.IsNoneTy()) {
    var.addError() << "Could not resolve the type of this variable";
  }
}

void CastCreator::create_int_cast(Expression &exp, const SizedType &target_type)
{
  // We don't need a cast if it's a literal
  if (target_type.IsIntegerTy()) {
    if (auto *integer = exp.as<Integer>()) {
      exp = ctx_.make_node<Integer>(
          Location(exp.loc()), integer->value, target_type, integer->original);
      return;
    } else if (auto *negative_integer = exp.as<NegativeInteger>()) {
      exp = ctx_.make_node<NegativeInteger>(Location(exp.loc()),
                                            negative_integer->value,
                                            target_type);
      return;
    }
  }

  auto *typeof_r = ctx_.make_node<Typeof>(Location(exp.loc()), target_type);
  exp = ctx_.make_node<Cast>(Location(exp.loc()),
                             typeof_r,
                             clone(ctx_, exp.loc(), exp));
  visit(exp);
}

} // namespace bpftrace::ast
