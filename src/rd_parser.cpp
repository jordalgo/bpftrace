#include "rd_parser.h"
#include <iostream>

namespace bpftrace {

RecursiveDescentParser::RecursiveDescentParser(ast::ASTContext &ctx, RecursiveDescentLexer &lexer)
    : ctx_(ctx), lexer_(lexer), had_error_(false) {}

bool RecursiveDescentParser::match(TokenType type) {
  if (check(type)) {
    advance();
    return true;
  }
  return false;
}

bool RecursiveDescentParser::check(TokenType type) const {
  return current().type == type;
}

Token RecursiveDescentParser::advance() {
  Token prev = current();
  lexer_.next();
  return prev;
}

Token RecursiveDescentParser::consume(TokenType type, const std::string &message) {
  if (check(type)) {
    return advance();
  }
  error(message);
  return current();
}

void RecursiveDescentParser::error(const std::string &message) {
  std::cerr << "Parse error at line " << current().loc.start.line
            << ", column " << current().loc.start.column
            << ": " << message << std::endl;
  had_error_ = true;
}

void RecursiveDescentParser::synchronize() {
  advance();

  while (!check(TokenType::END)) {
    if (current().type == TokenType::SEMI) {
      advance();
      return;
    }

    switch (current().type) {
      case TokenType::IF:
      case TokenType::WHILE:
      case TokenType::FOR:
      case TokenType::RETURN:
      case TokenType::LET:
        return;
      default:
        break;
    }

    advance();
  }
}

ast::Operator RecursiveDescentParser::token_to_operator(TokenType type) const {
  switch (type) {
    case TokenType::PLUS: return ast::Operator::PLUS;
    case TokenType::MINUS: return ast::Operator::MINUS;
    case TokenType::MUL: return ast::Operator::MUL;
    case TokenType::DIV: return ast::Operator::DIV;
    case TokenType::MOD: return ast::Operator::MOD;
    case TokenType::EQ: return ast::Operator::EQ;
    case TokenType::NE: return ast::Operator::NE;
    case TokenType::LT: return ast::Operator::LT;
    case TokenType::LE: return ast::Operator::LE;
    case TokenType::GT: return ast::Operator::GT;
    case TokenType::GE: return ast::Operator::GE;
    case TokenType::LAND: return ast::Operator::LAND;
    case TokenType::LOR: return ast::Operator::LOR;
    case TokenType::LNOT: return ast::Operator::LNOT;
    case TokenType::BAND: return ast::Operator::BAND;
    case TokenType::BOR: return ast::Operator::BOR;
    case TokenType::BXOR: return ast::Operator::BXOR;
    case TokenType::BNOT: return ast::Operator::BNOT;
    case TokenType::LEFT: return ast::Operator::LEFT;
    case TokenType::RIGHT: return ast::Operator::RIGHT;
    default: return ast::Operator::PLUS; // Default fallback
  }
}

// Expression parsing
ast::Expression RecursiveDescentParser::expression() {
  return ternary();
}

ast::Expression RecursiveDescentParser::ternary() {
  auto expr = logical_or();

  if (match(TokenType::QUES)) {
    auto true_expr = expression();
    consume(TokenType::COLON, "Expected ':' after true branch of ternary");
    auto false_expr = expression();
    auto loc = current().loc;
    return ctx_.make_node<ast::IfExpr>(loc, expr, true_expr, false_expr);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::logical_or() {
  auto expr = logical_and();

  while (match(TokenType::LOR)) {
    auto op = token_to_operator(TokenType::LOR);
    auto loc = current().loc;
    auto right = logical_and();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::logical_and() {
  auto expr = bitwise_or();

  while (match(TokenType::LAND)) {
    auto op = token_to_operator(TokenType::LAND);
    auto loc = current().loc;
    auto right = bitwise_or();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::bitwise_or() {
  auto expr = bitwise_xor();

  while (match(TokenType::BOR)) {
    auto op = token_to_operator(TokenType::BOR);
    auto loc = current().loc;
    auto right = bitwise_xor();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::bitwise_xor() {
  auto expr = bitwise_and();

  while (match(TokenType::BXOR)) {
    auto op = token_to_operator(TokenType::BXOR);
    auto loc = current().loc;
    auto right = bitwise_and();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::bitwise_and() {
  auto expr = equality();

  while (match(TokenType::BAND)) {
    auto op = token_to_operator(TokenType::BAND);
    auto loc = current().loc;
    auto right = equality();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::equality() {
  auto expr = relational();

  while (match(TokenType::EQ) || match(TokenType::NE)) {
    auto op = token_to_operator(current().type);
    auto loc = current().loc;
    advance();
    auto right = relational();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::relational() {
  auto expr = shift();

  while (match(TokenType::LT) || match(TokenType::LE) ||
         match(TokenType::GT) || match(TokenType::GE)) {
    auto op = token_to_operator(current().type);
    auto loc = current().loc;
    advance();
    auto right = shift();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::shift() {
  auto expr = additive();

  while (match(TokenType::LEFT) || match(TokenType::RIGHT)) {
    auto op = token_to_operator(current().type);
    auto loc = current().loc;
    advance();
    auto right = additive();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::additive() {
  auto expr = multiplicative();

  while (match(TokenType::PLUS) || match(TokenType::MINUS)) {
    auto op = token_to_operator(current().type);
    auto loc = current().loc;
    advance();
    auto right = multiplicative();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::multiplicative() {
  auto expr = cast();

  while (match(TokenType::MUL) || match(TokenType::DIV) || match(TokenType::MOD)) {
    auto op = token_to_operator(current().type);
    auto loc = current().loc;
    advance();
    auto right = cast();
    expr = ctx_.make_node<ast::Binop>(loc, expr, op, right);
  }

  return expr;
}

ast::Expression RecursiveDescentParser::cast() {
  if (match(TokenType::LPAREN)) {
    auto loc = current().loc;

    // Try to parse as a type
    if (is_type_start()) {
      auto type = parse_any_type();
      consume(TokenType::RPAREN, "Expected ')' after type in cast");
      auto expr = unary();
      return ctx_.make_node<ast::Cast>(loc, type, expr);
    } else {
      // Not a cast, backtrack by parsing as expression
      // For simplicity in this prototype, we'll just parse the expression
      auto expr = expression();
      consume(TokenType::RPAREN, "Expected ')' after expression");
      return expr;
    }
  }

  return unary();
}

ast::Expression RecursiveDescentParser::unary() {
  if (match(TokenType::LNOT) || match(TokenType::BNOT) ||
      match(TokenType::MINUS) || match(TokenType::MUL)) {
    auto op = token_to_operator(current().type);
    auto loc = current().loc;
    advance();
    auto expr = unary();
    return ctx_.make_node<ast::Unop>(loc, expr, op);
  }

  if (match(TokenType::INCREMENT)) {
    auto loc = current().loc;
    auto expr = unary();
    return ctx_.make_node<ast::Unop>(loc, expr, ast::Operator::PRE_INCREMENT);
  }

  if (match(TokenType::DECREMENT)) {
    auto loc = current().loc;
    auto expr = unary();
    return ctx_.make_node<ast::Unop>(loc, expr, ast::Operator::PRE_DECREMENT);
  }

  if (match(TokenType::SIZEOF)) {
    auto loc = current().loc;
    consume(TokenType::LPAREN, "Expected '(' after 'sizeof'");

    if (is_type_start()) {
      auto type = parse_type();
      consume(TokenType::RPAREN, "Expected ')' after type");
      return ctx_.make_node<ast::Sizeof>(loc, type);
    } else {
      auto expr = expression();
      consume(TokenType::RPAREN, "Expected ')' after expression");
      return ctx_.make_node<ast::Sizeof>(loc, expr);
    }
  }

  return postfix();
}

ast::Expression RecursiveDescentParser::postfix() {
  auto expr = primary();

  while (true) {
    auto loc = current().loc;

    if (match(TokenType::INCREMENT)) {
      expr = ctx_.make_node<ast::Unop>(loc, expr, ast::Operator::POST_INCREMENT);
    } else if (match(TokenType::DECREMENT)) {
      expr = ctx_.make_node<ast::Unop>(loc, expr, ast::Operator::POST_DECREMENT);
    } else if (match(TokenType::LBRACKET)) {
      auto index = expression();
      consume(TokenType::RBRACKET, "Expected ']' after array index");
      expr = ctx_.make_node<ast::ArrayAccess>(loc, expr, index);
    } else if (match(TokenType::DOT)) {
      if (check(TokenType::INTEGER)) {
        // Tuple access
        auto tok = advance();
        uint64_t index = std::stoull(tok.value);
        expr = ctx_.make_node<ast::TupleAccess>(loc, expr, index);
      } else {
        // Field access
        auto field_tok = consume(TokenType::IDENTIFIER, "Expected field name after '.'");
        expr = ctx_.make_node<ast::FieldAccess>(loc, expr, field_tok.value);
      }
    } else if (match(TokenType::PTR)) {
      auto field_tok = consume(TokenType::IDENTIFIER, "Expected field name after '->'");
      expr = ctx_.make_node<ast::FieldAccess>(loc, expr, field_tok.value);
    } else if (match(TokenType::LPAREN)) {
      // Function call - need to handle this in primary for identifiers
      break;
    } else {
      break;
    }
  }

  return expr;
}

ast::Expression RecursiveDescentParser::primary() {
  auto loc = current().loc;

  if (match(TokenType::BOOL)) {
    bool value = (current().value == "true");
    return ctx_.make_node<ast::Boolean>(loc, value);
  }

  if (match(TokenType::INTEGER)) {
    auto tok = current();
    auto res = util::to_uint(tok.value, 0);
    if (res) {
      return ctx_.make_node<ast::Integer>(loc, *res, tok.value);
    } else {
      error("Invalid integer literal");
      return ctx_.make_node<ast::Integer>(loc, 0, "0");
    }
  }

  if (match(TokenType::STRING)) {
    auto value = current().value;
    return ctx_.make_node<ast::String>(loc, value);
  }

  if (match(TokenType::BUILTIN)) {
    auto name = current().value;
    return ctx_.make_node<ast::Builtin>(loc, name);
  }

  if (match(TokenType::VAR)) {
    auto name = current().value;
    return ctx_.make_node<ast::Variable>(loc, name);
  }

  if (match(TokenType::MAP)) {
    auto name = current().value;
    auto map = ctx_.make_node<ast::Map>(loc, name);

    if (match(TokenType::LBRACKET)) {
      ast::ExpressionList args;
      if (!check(TokenType::RBRACKET)) {
        do {
          args.push_back(expression());
        } while (match(TokenType::COMMA));
      }
      consume(TokenType::RBRACKET, "Expected ']' after map key");

      if (args.size() > 1) {
        auto tuple = ctx_.make_node<ast::Tuple>(loc, std::move(args));
        return ctx_.make_node<ast::MapAccess>(loc, map, tuple);
      } else if (args.size() == 1) {
        return ctx_.make_node<ast::MapAccess>(loc, map, args[0]);
      }
    }

    return map;
  }

  if (match(TokenType::IDENTIFIER)) {
    auto name = current().value;

    // Check if it's a function call
    if (match(TokenType::LPAREN)) {
      ast::ExpressionList args;
      if (!check(TokenType::RPAREN)) {
        do {
          args.push_back(expression());
        } while (match(TokenType::COMMA));
      }
      consume(TokenType::RPAREN, "Expected ')' after function arguments");
      return ctx_.make_node<ast::Call>(loc, name, std::move(args));
    }

    return ctx_.make_node<ast::Identifier>(loc, name);
  }

  if (match(TokenType::LPAREN)) {
    // Could be tuple or grouped expression
    if (check(TokenType::RPAREN)) {
      consume(TokenType::RPAREN, "Expected ')'");
      return ctx_.make_node<ast::Tuple>(loc, ast::ExpressionList{});
    }

    auto first = expression();

    if (match(TokenType::COMMA)) {
      ast::ExpressionList elements;
      elements.push_back(first);

      do {
        if (check(TokenType::RPAREN)) break;
        elements.push_back(expression());
      } while (match(TokenType::COMMA));

      consume(TokenType::RPAREN, "Expected ')' after tuple elements");
      return ctx_.make_node<ast::Tuple>(loc, std::move(elements));
    }

    consume(TokenType::RPAREN, "Expected ')' after expression");
    return first;
  }

  if (match(TokenType::LBRACE)) {
    auto stmts = statement_list();

    ast::Expression final_expr;
    if (!check(TokenType::RBRACE) && !check(TokenType::SEMI)) {
      final_expr = expression();
    } else {
      final_expr = ctx_.make_node<ast::None>(loc);
    }

    consume(TokenType::RBRACE, "Expected '}' after block");
    return ctx_.make_node<ast::BlockExpr>(loc, std::move(stmts), final_expr);
  }

  error("Expected expression, got '" + current().value + "'");
  return ctx_.make_node<ast::Integer>(loc, 0, "0");
}

// Statement parsing
ast::StatementList RecursiveDescentParser::statement_list() {
  ast::StatementList stmts;

  while (!check(TokenType::RBRACE) && !check(TokenType::END)) {
    stmts.push_back(statement());
  }

  return stmts;
}

ast::Statement RecursiveDescentParser::statement() {
  auto loc = current().loc;

  if (check(TokenType::IF)) {
    return ctx_.make_node<ast::ExprStatement>(loc, if_statement());
  }

  if (check(TokenType::WHILE) || check(TokenType::UNROLL)) {
    return while_statement();
  }

  if (check(TokenType::FOR)) {
    return for_statement();
  }

  if (check(TokenType::RETURN) || check(TokenType::BREAK) || check(TokenType::CONTINUE)) {
    return jump_statement();
  }

  if (check(TokenType::LET)) {
    return declaration_statement();
  }

  if (check(TokenType::LBRACE)) {
    return block_statement();
  }

  // Try assignment or expression statement
  auto expr = expression();

  if (is_assignment_op()) {
    return assignment_statement();
  }

  consume(TokenType::SEMI, "Expected ';' after expression");
  return ctx_.make_node<ast::ExprStatement>(loc, expr);
}

ast::Statement RecursiveDescentParser::expression_statement() {
  auto loc = current().loc;
  auto expr = expression();
  consume(TokenType::SEMI, "Expected ';' after expression");
  return ctx_.make_node<ast::ExprStatement>(loc, expr);
}

ast::Statement RecursiveDescentParser::declaration_statement() {
  auto loc = current().loc;
  consume(TokenType::LET, "Expected 'let'");

  auto var_tok = consume(TokenType::VAR, "Expected variable name");
  auto var = ctx_.make_node<ast::Variable>(loc, var_tok.value);

  ast::Typeof *type = nullptr;
  if (match(TokenType::COLON)) {
    type = parse_any_type();
  }

  auto decl = ctx_.make_node<ast::VarDeclStatement>(loc, var, type);

  if (match(TokenType::ASSIGN)) {
    auto init = expression();
    consume(TokenType::SEMI, "Expected ';' after variable declaration");
    return ctx_.make_node<ast::AssignVarStatement>(loc, decl, init);
  }

  consume(TokenType::SEMI, "Expected ';' after variable declaration");
  return decl;
}

ast::Statement RecursiveDescentParser::assignment_statement() {
  auto loc = current().loc;

  // This is simplified - in reality we need to parse LHS properly
  auto lhs = expression();

  if (match(TokenType::ASSIGN)) {
    auto rhs = expression();
    consume(TokenType::SEMI, "Expected ';' after assignment");

    // Determine assignment type based on LHS
    if (auto *var = std::get_if<ast::Variable *>(&lhs.value)) {
      return ctx_.make_node<ast::AssignVarStatement>(loc, *var, rhs);
    } else if (auto *map = std::get_if<ast::Map *>(&lhs.value)) {
      return ctx_.make_node<ast::AssignScalarMapStatement>(loc, *map, rhs);
    } else if (auto *map_access = std::get_if<ast::MapAccess *>(&lhs.value)) {
      return ctx_.make_node<ast::AssignMapStatement>(loc, *map_access, rhs);
    }
  }

  error("Invalid assignment target");
  return ctx_.make_node<ast::ExprStatement>(loc, lhs);
}

ast::Statement RecursiveDescentParser::jump_statement() {
  auto loc = current().loc;

  if (match(TokenType::RETURN)) {
    if (check(TokenType::SEMI)) {
      consume(TokenType::SEMI, "Expected ';'");
      return ctx_.make_node<ast::Jump>(loc, ast::JumpType::RETURN);
    }
    auto expr = expression();
    consume(TokenType::SEMI, "Expected ';' after return value");
    return ctx_.make_node<ast::Jump>(loc, ast::JumpType::RETURN, expr);
  }

  if (match(TokenType::BREAK)) {
    consume(TokenType::SEMI, "Expected ';' after break");
    return ctx_.make_node<ast::Jump>(loc, ast::JumpType::BREAK);
  }

  if (match(TokenType::CONTINUE)) {
    consume(TokenType::SEMI, "Expected ';' after continue");
    return ctx_.make_node<ast::Jump>(loc, ast::JumpType::CONTINUE);
  }

  error("Expected jump statement");
  return ctx_.make_node<ast::Jump>(loc, ast::JumpType::BREAK);
}

ast::Statement RecursiveDescentParser::block_statement() {
  auto loc = current().loc;
  auto block = none_block();
  return ctx_.make_node<ast::ExprStatement>(loc, block);
}

ast::IfExpr *RecursiveDescentParser::if_statement() {
  auto loc = current().loc;
  consume(TokenType::IF, "Expected 'if'");

  auto cond = expression();
  auto then_block = none_block();

  if (match(TokenType::ELSE)) {
    if (check(TokenType::IF)) {
      auto else_if = if_statement();
      return ctx_.make_node<ast::IfExpr>(loc, cond, then_block, else_if);
    } else {
      auto else_block = none_block();
      return ctx_.make_node<ast::IfExpr>(loc, cond, then_block, else_block);
    }
  }

  auto none = ctx_.make_node<ast::None>(loc);
  return ctx_.make_node<ast::IfExpr>(loc, cond, then_block, none);
}

ast::Statement RecursiveDescentParser::while_statement() {
  auto loc = current().loc;
  bool is_unroll = match(TokenType::UNROLL);

  if (!is_unroll) {
    consume(TokenType::WHILE, "Expected 'while'");
  }

  auto cond = expression();
  auto body = none_block();

  if (is_unroll) {
    return ctx_.make_node<ast::Unroll>(loc, cond, body);
  }
  return ctx_.make_node<ast::While>(loc, cond, body);
}

ast::Statement RecursiveDescentParser::for_statement() {
  auto loc = current().loc;
  consume(TokenType::FOR, "Expected 'for'");

  bool has_paren = match(TokenType::LPAREN);

  auto var_tok = consume(TokenType::VAR, "Expected variable in for loop");
  auto var = ctx_.make_node<ast::Variable>(loc, var_tok.value);

  consume(TokenType::COLON, "Expected ':' in for loop");

  auto iterable = expression();

  if (has_paren) {
    consume(TokenType::RPAREN, "Expected ')' after for header");
  }

  auto body = none_block();

  // Determine if it's a map or range iteration
  if (auto *map = std::get_if<ast::Map *>(&iterable.value)) {
    return ctx_.make_node<ast::For>(loc, var, *map, std::move(body));
  }

  error("For loop requires map or range");
  return ctx_.make_node<ast::ExprStatement>(loc, iterable);
}

// Top-level parsing
ast::Program *RecursiveDescentParser::parse_program() {
  std::string header = "";
  ast::CStatementList c_defs;
  ast::Config *config = nullptr;
  ast::RootImportList imports;
  ast::RootStatements root_stmts;

  auto loc = current().loc;

  // Parse header if present
  if (check(TokenType::HEADER)) {
    header = current().value;
    advance();
  }

  // Parse config if present
  if (check(TokenType::CONFIG)) {
    // Simplified config parsing
    advance();
  }

  // Parse probes
  while (!check(TokenType::END)) {
    auto attach_pts = attach_points();
    auto pred = predicate();
    auto body = none_block();

    auto *block = body;
    if (pred.has_value()) {
      auto *none = ctx_.make_node<ast::None>(loc);
      auto *cond = ctx_.make_node<ast::IfExpr>(loc, pred.value(), block, none);
      block = ctx_.make_node<ast::BlockExpr>(loc, ast::StatementList{}, cond);
    }

    auto probe = ctx_.make_node<ast::Probe>(loc, std::move(attach_pts), block);
    root_stmts.push_back(probe);
  }

  return ctx_.make_node<ast::Program>(loc, std::move(c_defs), config,
                                      std::move(imports), std::move(root_stmts), header);
}

std::optional<ast::Expression> RecursiveDescentParser::parse_expr() {
  try {
    return expression();
  } catch (...) {
    return std::nullopt;
  }
}

ast::AttachPointList RecursiveDescentParser::attach_points() {
  ast::AttachPointList points;

  do {
    points.push_back(attach_point());
  } while (match(TokenType::COMMA));

  return points;
}

ast::AttachPoint *RecursiveDescentParser::attach_point() {
  auto loc = current().loc;
  auto def = attach_point_def();
  return ctx_.make_node<ast::AttachPoint>(loc, def, false);
}

std::string RecursiveDescentParser::attach_point_def() {
  std::string def;

  while (!check(TokenType::DIV) && !check(TokenType::LBRACE) &&
         !check(TokenType::COMMA) && !check(TokenType::END)) {
    def += current().value;
    advance();
  }

  return def;
}

std::optional<ast::Expression> RecursiveDescentParser::predicate() {
  if (match(TokenType::DIV)) {
    auto expr = expression();
    consume(TokenType::ENDPRED, "Expected '/' to end predicate");
    return expr;
  }
  return std::nullopt;
}

ast::BlockExpr *RecursiveDescentParser::block() {
  auto loc = current().loc;
  consume(TokenType::LBRACE, "Expected '{'");

  auto stmts = statement_list();

  ast::Expression final_expr;
  if (!check(TokenType::RBRACE) && !check(TokenType::SEMI)) {
    final_expr = expression();
  } else {
    final_expr = ctx_.make_node<ast::None>(loc);
  }

  consume(TokenType::RBRACE, "Expected '}'");
  return ctx_.make_node<ast::BlockExpr>(loc, std::move(stmts), final_expr);
}

ast::BlockExpr *RecursiveDescentParser::none_block() {
  auto loc = current().loc;
  consume(TokenType::LBRACE, "Expected '{'");

  auto stmts = statement_list();

  consume(TokenType::RBRACE, "Expected '}'");
  auto none = ctx_.make_node<ast::None>(loc);
  return ctx_.make_node<ast::BlockExpr>(loc, std::move(stmts), none);
}

// Type parsing
SizedType RecursiveDescentParser::parse_type() {
  if (check(TokenType::INT_TYPE)) {
    auto type_name = current().value;
    advance();

    // Simplified - return appropriate type
    if (type_name == "int64") return CreateInt(64);
    if (type_name == "int32") return CreateInt(32);
    if (type_name == "int16") return CreateInt(16);
    if (type_name == "int8") return CreateInt(8);
    if (type_name == "uint64") return CreateUInt(64);
    if (type_name == "uint32") return CreateUInt(32);
    if (type_name == "uint16") return CreateUInt(16);
    if (type_name == "uint8") return CreateUInt(8);
    if (type_name == "bool") return CreateBool();

    return CreateInt(64);
  }

  if (check(TokenType::BUILTIN_TYPE)) {
    auto type_name = current().value;
    advance();

    if (type_name == "void") return CreateVoid();
    if (type_name == "count_t") return CreateCount();

    return CreateInt(64);
  }

  error("Expected type");
  return CreateInt(64);
}

ast::Typeof *RecursiveDescentParser::parse_any_type() {
  auto loc = current().loc;
  auto type = parse_type();
  return ctx_.make_node<ast::Typeof>(loc, type);
}

bool RecursiveDescentParser::is_type_start() const {
  return check(TokenType::INT_TYPE) || check(TokenType::BUILTIN_TYPE) ||
         check(TokenType::SIZED_TYPE) || check(TokenType::STRUCT);
}

bool RecursiveDescentParser::is_assignment_op() const {
  return check(TokenType::ASSIGN) || check(TokenType::PLUSASSIGN) ||
         check(TokenType::MINUSASSIGN) || check(TokenType::MULASSIGN) ||
         check(TokenType::DIVASSIGN) || check(TokenType::MODASSIGN) ||
         check(TokenType::LEFTASSIGN) || check(TokenType::RIGHTASSIGN) ||
         check(TokenType::BANDASSIGN) || check(TokenType::BORASSIGN) ||
         check(TokenType::BXORASSIGN);
}

} // namespace bpftrace
