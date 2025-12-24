#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "ast/location.h"

namespace bpftrace {

enum class TokenType {
  END,

  // Keywords
  IF,
  ELSE,
  WHILE,
  FOR,
  RETURN,
  BREAK,
  CONTINUE,
  SIZEOF,
  OFFSETOF,
  TYPEOF,
  TYPEINFO,
  LET,
  IMPORT,
  CONFIG,
  UNROLL,
  STRUCT,
  UNION,
  ENUM,
  SUBPROG,
  MACRO,
  COMPTIME,

  // Literals
  IDENTIFIER,
  INTEGER,
  STRING,
  BOOL,
  PATH,
  BUILTIN,

  // Types
  INT_TYPE,
  BUILTIN_TYPE,
  SIZED_TYPE,

  // Variables and maps
  MAP,
  VAR,
  PARAM,
  PARAMCOUNT,

  // Operators
  PLUS,
  MINUS,
  MUL,
  DIV,
  MOD,
  ASSIGN,
  EQ,
  NE,
  LT,
  LE,
  GT,
  GE,
  LAND,
  LOR,
  LNOT,
  BAND,
  BOR,
  BXOR,
  BNOT,
  LEFT,
  RIGHT,
  INCREMENT,
  DECREMENT,

  // Compound assignment
  PLUSASSIGN,
  MINUSASSIGN,
  MULASSIGN,
  DIVASSIGN,
  MODASSIGN,
  LEFTASSIGN,
  RIGHTASSIGN,
  BANDASSIGN,
  BORASSIGN,
  BXORASSIGN,

  // Delimiters
  LPAREN,
  RPAREN,
  LBRACE,
  RBRACE,
  LBRACKET,
  RBRACKET,
  SEMI,
  COMMA,
  DOT,
  COLON,
  QUES,
  PTR,
  UNDERSCORE,

  // Special
  ENDPRED,
  CPREPROC,
  STRUCT_DEFN,
  HEADER,

  INVALID,
};

struct Token {
  TokenType type;
  std::string value;
  ast::SourceLocation loc;

  Token() : type(TokenType::INVALID), value(""), loc(nullptr) {}
  Token(TokenType t, std::string v, ast::SourceLocation l)
      : type(t), value(std::move(v)), loc(l) {}
};

class RecursiveDescentLexer {
public:
  explicit RecursiveDescentLexer(const std::string &source, const std::string *source_ref);

  Token next();
  Token peek();
  const Token &current() const { return current_token_; }

  ast::SourceLocation location() const;

private:
  char advance();
  char peek_char() const;
  char peek_next_char() const;
  bool is_at_end() const;

  void skip_whitespace();
  void skip_comment();

  Token make_token(TokenType type, std::string value = "");
  Token scan_identifier();
  Token scan_number();
  Token scan_string();
  Token scan_path();
  Token scan_map();
  Token scan_var();
  Token scan_param();
  Token scan_operator();

  bool is_digit(char c) const;
  bool is_alpha(char c) const;
  bool is_alnum(char c) const;

  TokenType keyword_type(const std::string &text) const;

  const std::string &source_;
  const std::string *source_ref_;
  size_t pos_;
  size_t line_;
  size_t column_;
  Token current_token_;

  static const std::unordered_map<std::string, TokenType> keywords_;
  static const std::unordered_map<std::string, TokenType> builtin_types_;
  static const std::unordered_map<std::string, TokenType> int_types_;
  static const std::unordered_map<std::string, TokenType> sized_types_;
};

} // namespace bpftrace
