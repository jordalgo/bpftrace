#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ast/ast.h"
#include "ast/context.h"
#include "rd_lexer.h"

namespace bpftrace {

class RecursiveDescentParser {
public:
  RecursiveDescentParser(ast::ASTContext &ctx, RecursiveDescentLexer &lexer);

  ast::Program *parse_program();
  std::optional<ast::Expression> parse_expr();

private:
  // Token management
  bool match(TokenType type);
  bool check(TokenType type) const;
  Token advance();
  Token consume(TokenType type, const std::string &message);
  Token current() const { return lexer_.current(); }

  void error(const std::string &message);
  void synchronize();

  // Grammar rules - Expressions
  ast::Expression expression();
  ast::Expression ternary();
  ast::Expression logical_or();
  ast::Expression logical_and();
  ast::Expression bitwise_or();
  ast::Expression bitwise_xor();
  ast::Expression bitwise_and();
  ast::Expression equality();
  ast::Expression relational();
  ast::Expression shift();
  ast::Expression additive();
  ast::Expression multiplicative();
  ast::Expression cast();
  ast::Expression unary();
  ast::Expression postfix();
  ast::Expression primary();

  // Grammar rules - Statements
  ast::Statement statement();
  ast::Statement expression_statement();
  ast::Statement declaration_statement();
  ast::Statement assignment_statement();
  ast::Statement jump_statement();
  ast::Statement block_statement();
  ast::IfExpr *if_statement();
  ast::Statement while_statement();
  ast::Statement for_statement();
  ast::StatementList statement_list();

  // Grammar rules - Top level
  ast::AttachPointList attach_points();
  ast::AttachPoint *attach_point();
  std::string attach_point_def();
  std::optional<ast::Expression> predicate();
  ast::BlockExpr *block();
  ast::BlockExpr *none_block();

  // Type parsing
  SizedType parse_type();
  ast::Typeof *parse_any_type();

  // Helper methods
  bool is_type_start() const;
  bool is_assignment_op() const;
  ast::Operator token_to_operator(TokenType type) const;

  ast::ASTContext &ctx_;
  RecursiveDescentLexer &lexer_;
  bool had_error_;
};

} // namespace bpftrace
