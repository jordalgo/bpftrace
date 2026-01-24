#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"

namespace bpftrace {
class BPFtrace;
} // namespace bpftrace

namespace bpftrace::ast {

class CastCreator : public Visitor<CastCreator> {
public:
  explicit CastCreator(ASTContext &ast, BPFtrace &bpftrace);

  using Visitor<CastCreator>::visit;
  void visit(AssignVarStatement &assignment);
  void visit(Binop &binop);
  void visit(BlockExpr &block);
  void visit(Cast &cast);
  void visit(IfExpr &if_expr);
  void visit(Variable &var);

private:
  ASTContext &ctx_;
  BPFtrace &bpftrace_;

  void create_int_cast(Expression &exp, const SizedType &target_type);
};

} // namespace bpftrace::ast
