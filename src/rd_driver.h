#pragma once

#include <optional>
#include <string>

#include "ast/ast.h"
#include "ast/context.h"
#include "rd_lexer.h"
#include "rd_parser.h"

namespace bpftrace {

class RecursiveDescentDriver {
public:
  explicit RecursiveDescentDriver(ast::ASTContext &ctx, bool debug = false)
      : ctx(ctx), debug(debug) {}

  ast::Program *parse_program(const std::string &source);
  std::optional<ast::Expression> parse_expr(const std::string &source);

  void error(const ast::SourceLocation &l, const std::string &m);

  ast::ASTContext &ctx;
  const bool debug;

private:
  const std::string *source_ref_ = nullptr;
};

} // namespace bpftrace
