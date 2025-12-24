#include "rd_lexer.h"
#include <cctype>
#include <algorithm>

namespace bpftrace {

const std::unordered_map<std::string, TokenType> RecursiveDescentLexer::keywords_ = {
  {"if", TokenType::IF},
  {"else", TokenType::ELSE},
  {"while", TokenType::WHILE},
  {"for", TokenType::FOR},
  {"return", TokenType::RETURN},
  {"break", TokenType::BREAK},
  {"continue", TokenType::CONTINUE},
  {"sizeof", TokenType::SIZEOF},
  {"offsetof", TokenType::OFFSETOF},
  {"typeof", TokenType::TYPEOF},
  {"typeinfo", TokenType::TYPEINFO},
  {"let", TokenType::LET},
  {"import", TokenType::IMPORT},
  {"config", TokenType::CONFIG},
  {"unroll", TokenType::UNROLL},
  {"struct", TokenType::STRUCT},
  {"union", TokenType::UNION},
  {"enum", TokenType::ENUM},
  {"fn", TokenType::SUBPROG},
  {"macro", TokenType::MACRO},
  {"comptime", TokenType::COMPTIME},
  {"true", TokenType::BOOL},
  {"false", TokenType::BOOL},
};

const std::unordered_map<std::string, TokenType> RecursiveDescentLexer::int_types_ = {
  {"bool", TokenType::INT_TYPE},
  {"int8", TokenType::INT_TYPE},
  {"int16", TokenType::INT_TYPE},
  {"int32", TokenType::INT_TYPE},
  {"int64", TokenType::INT_TYPE},
  {"uint8", TokenType::INT_TYPE},
  {"uint16", TokenType::INT_TYPE},
  {"uint32", TokenType::INT_TYPE},
  {"uint64", TokenType::INT_TYPE},
};

const std::unordered_map<std::string, TokenType> RecursiveDescentLexer::builtin_types_ = {
  {"void", TokenType::BUILTIN_TYPE},
  {"min_t", TokenType::BUILTIN_TYPE},
  {"max_t", TokenType::BUILTIN_TYPE},
  {"sum_t", TokenType::BUILTIN_TYPE},
  {"count_t", TokenType::BUILTIN_TYPE},
  {"avg_t", TokenType::BUILTIN_TYPE},
  {"stats_t", TokenType::BUILTIN_TYPE},
  {"umin_t", TokenType::BUILTIN_TYPE},
  {"umax_t", TokenType::BUILTIN_TYPE},
  {"usum_t", TokenType::BUILTIN_TYPE},
  {"uavg_t", TokenType::BUILTIN_TYPE},
  {"ustats_t", TokenType::BUILTIN_TYPE},
  {"timestamp", TokenType::BUILTIN_TYPE},
  {"macaddr_t", TokenType::BUILTIN_TYPE},
  {"cgroup_path_t", TokenType::BUILTIN_TYPE},
  {"kstack_t", TokenType::BUILTIN_TYPE},
  {"ustack_t", TokenType::BUILTIN_TYPE},
  {"ksym_t", TokenType::BUILTIN_TYPE},
  {"usym_t", TokenType::BUILTIN_TYPE},
  {"probe_t", TokenType::BUILTIN_TYPE},
  {"username_t", TokenType::BUILTIN_TYPE},
  {"lhist_t", TokenType::BUILTIN_TYPE},
  {"hist_t", TokenType::BUILTIN_TYPE},
  {"tseries_t", TokenType::BUILTIN_TYPE},
};

const std::unordered_map<std::string, TokenType> RecursiveDescentLexer::sized_types_ = {
  {"inet", TokenType::SIZED_TYPE},
  {"buffer", TokenType::SIZED_TYPE},
  {"string", TokenType::SIZED_TYPE},
};

RecursiveDescentLexer::RecursiveDescentLexer(const std::string &source, const std::string *source_ref)
    : source_(source), source_ref_(source_ref), pos_(0), line_(1), column_(1) {
  current_token_ = next();
}

char RecursiveDescentLexer::advance() {
  if (is_at_end()) return '\0';
  char c = source_[pos_++];
  if (c == '\n') {
    line_++;
    column_ = 1;
  } else {
    column_++;
  }
  return c;
}

char RecursiveDescentLexer::peek_char() const {
  if (is_at_end()) return '\0';
  return source_[pos_];
}

char RecursiveDescentLexer::peek_next_char() const {
  if (pos_ + 1 >= source_.size()) return '\0';
  return source_[pos_ + 1];
}

bool RecursiveDescentLexer::is_at_end() const {
  return pos_ >= source_.size();
}

void RecursiveDescentLexer::skip_whitespace() {
  while (!is_at_end()) {
    char c = peek_char();
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      advance();
    } else if (c == '/' && peek_next_char() == '/') {
      // C++ style comment
      while (!is_at_end() && peek_char() != '\n') {
        advance();
      }
    } else if (c == '/' && peek_next_char() == '*') {
      // C style comment
      advance(); // '/'
      advance(); // '*'
      while (!is_at_end()) {
        if (peek_char() == '*' && peek_next_char() == '/') {
          advance(); // '*'
          advance(); // '/'
          break;
        }
        advance();
      }
    } else {
      break;
    }
  }
}

Token RecursiveDescentLexer::make_token(TokenType type, std::string value) {
  return Token(type, std::move(value), location());
}

ast::SourceLocation RecursiveDescentLexer::location() const {
  return ast::SourceLocation(source_ref_, line_, column_);
}

bool RecursiveDescentLexer::is_digit(char c) const {
  return std::isdigit(static_cast<unsigned char>(c));
}

bool RecursiveDescentLexer::is_alpha(char c) const {
  return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

bool RecursiveDescentLexer::is_alnum(char c) const {
  return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

TokenType RecursiveDescentLexer::keyword_type(const std::string &text) const {
  auto it = keywords_.find(text);
  if (it != keywords_.end()) {
    return it->second;
  }

  it = int_types_.find(text);
  if (it != int_types_.end()) {
    return TokenType::INT_TYPE;
  }

  it = builtin_types_.find(text);
  if (it != builtin_types_.end()) {
    return TokenType::BUILTIN_TYPE;
  }

  it = sized_types_.find(text);
  if (it != sized_types_.end()) {
    return TokenType::SIZED_TYPE;
  }

  // Check if it's a builtin identifier like arg0, nsecs, etc.
  if (text.find("arg") == 0 || text.find("sarg") == 0 ||
      text == "args" || text == "ctx" || text == "kstack" ||
      text == "nsecs" || text == "pid" || text == "tid" ||
      text == "ustack" || text.find("__builtin_") == 0) {
    return TokenType::BUILTIN;
  }

  return TokenType::IDENTIFIER;
}

Token RecursiveDescentLexer::scan_identifier() {
  size_t start = pos_;
  size_t start_col = column_;

  while (is_alnum(peek_char())) {
    advance();
  }

  std::string text = source_.substr(start, pos_ - start);
  TokenType type = keyword_type(text);

  return Token(type, text, ast::SourceLocation(source_ref_, line_, start_col));
}

Token RecursiveDescentLexer::scan_number() {
  size_t start = pos_;
  size_t start_col = column_;

  // Handle hex numbers
  if (peek_char() == '0' && (peek_next_char() == 'x' || peek_next_char() == 'X')) {
    advance(); // '0'
    advance(); // 'x' or 'X'
    while (std::isxdigit(static_cast<unsigned char>(peek_char()))) {
      advance();
    }
  } else {
    // Decimal number
    while (is_digit(peek_char()) || peek_char() == '_') {
      advance();
    }

    // Handle scientific notation
    if (peek_char() == 'e' || peek_char() == 'E') {
      advance();
      if (peek_char() == '+' || peek_char() == '-') {
        advance();
      }
      while (is_digit(peek_char())) {
        advance();
      }
    }
  }

  // Handle suffixes like 'ns', 'us', 'ms', 's', 'm', 'h', 'd', 'u', 'l', 'll'
  if (peek_char() == 'n' && peek_next_char() == 's') {
    advance(); advance();
  } else if (peek_char() == 'u' && peek_next_char() == 's') {
    advance(); advance();
  } else if (peek_char() == 'm' && peek_next_char() == 's') {
    advance(); advance();
  } else if (peek_char() == 's' || peek_char() == 'm' ||
             peek_char() == 'h' || peek_char() == 'd') {
    advance();
  } else if (peek_char() == 'u' || peek_char() == 'U') {
    advance();
    if (peek_char() == 'l' || peek_char() == 'L') {
      advance();
      if (peek_char() == 'l' || peek_char() == 'L') {
        advance();
      }
    }
  } else if (peek_char() == 'l' || peek_char() == 'L') {
    advance();
    if (peek_char() == 'l' || peek_char() == 'L') {
      advance();
    }
  }

  std::string text = source_.substr(start, pos_ - start);
  return Token(TokenType::INTEGER, text, ast::SourceLocation(source_ref_, line_, start_col));
}

Token RecursiveDescentLexer::scan_string() {
  size_t start_col = column_;
  advance(); // Opening quote

  std::string value;
  while (!is_at_end() && peek_char() != '"') {
    if (peek_char() == '\\') {
      advance();
      if (is_at_end()) break;
      char c = advance();
      switch (c) {
        case 'n': value += '\n'; break;
        case 't': value += '\t'; break;
        case 'r': value += '\r'; break;
        case '"': value += '"'; break;
        case '\\': value += '\\'; break;
        default: value += c; break;
      }
    } else {
      value += advance();
    }
  }

  if (!is_at_end()) {
    advance(); // Closing quote
  }

  return Token(TokenType::STRING, value, ast::SourceLocation(source_ref_, line_, start_col));
}

Token RecursiveDescentLexer::scan_path() {
  size_t start = pos_;
  size_t start_col = column_;

  advance(); // ':'
  while (!is_at_end()) {
    char c = peek_char();
    if (is_alnum(c) || c == '_' || c == '-' || c == '.' || c == '/' ||
        c == '#' || c == '$' || c == '+' || c == '*' || c == '\\') {
      advance();
    } else {
      break;
    }
  }

  std::string text = source_.substr(start, pos_ - start);
  return Token(TokenType::PATH, text, ast::SourceLocation(source_ref_, line_, start_col));
}

Token RecursiveDescentLexer::scan_map() {
  size_t start = pos_;
  size_t start_col = column_;

  advance(); // '@'
  while (is_alnum(peek_char())) {
    advance();
  }

  std::string text = source_.substr(start, pos_ - start);
  return Token(TokenType::MAP, text, ast::SourceLocation(source_ref_, line_, start_col));
}

Token RecursiveDescentLexer::scan_var() {
  size_t start = pos_;
  size_t start_col = column_;

  advance(); // '$'
  while (is_alnum(peek_char())) {
    advance();
  }

  std::string text = source_.substr(start, pos_ - start);
  return Token(TokenType::VAR, text, ast::SourceLocation(source_ref_, line_, start_col));
}

Token RecursiveDescentLexer::scan_param() {
  size_t start = pos_;
  size_t start_col = column_;

  advance(); // '$'

  if (peek_char() == '#') {
    advance();
    return Token(TokenType::PARAMCOUNT, "$#", ast::SourceLocation(source_ref_, line_, start_col));
  }

  while (is_digit(peek_char())) {
    advance();
  }

  std::string text = source_.substr(start, pos_ - start);
  return Token(TokenType::PARAM, text, ast::SourceLocation(source_ref_, line_, start_col));
}

Token RecursiveDescentLexer::next() {
  skip_whitespace();

  if (is_at_end()) {
    return make_token(TokenType::END);
  }

  size_t start_col = column_;
  char c = peek_char();

  // Identifiers and keywords
  if (is_alpha(c)) {
    return scan_identifier();
  }

  // Numbers
  if (is_digit(c)) {
    return scan_number();
  }

  // String literals
  if (c == '"') {
    return scan_string();
  }

  // Path
  if (c == ':' && (is_alnum(peek_next_char()) || peek_next_char() == '/' || peek_next_char() == '\\')) {
    return scan_path();
  }

  // Map
  if (c == '@') {
    return scan_map();
  }

  // Variable or parameter
  if (c == '$') {
    if (is_digit(peek_next_char()) || peek_next_char() == '#') {
      return scan_param();
    }
    return scan_var();
  }

  // Operators and delimiters
  advance();

  switch (c) {
    case '(': return make_token(TokenType::LPAREN, "(");
    case ')': return make_token(TokenType::RPAREN, ")");
    case '{': return make_token(TokenType::LBRACE, "{");
    case '}': return make_token(TokenType::RBRACE, "}");
    case '[': return make_token(TokenType::LBRACKET, "[");
    case ']': return make_token(TokenType::RBRACKET, "]");
    case ';': return make_token(TokenType::SEMI, ";");
    case ',': return make_token(TokenType::COMMA, ",");
    case '?': return make_token(TokenType::QUES, "?");
    case '~': return make_token(TokenType::BNOT, "~");
    case '_': return make_token(TokenType::UNDERSCORE, "_");

    case ':': return make_token(TokenType::COLON, ":");
    case '.': return make_token(TokenType::DOT, ".");

    case '+':
      if (peek_char() == '+') {
        advance();
        return make_token(TokenType::INCREMENT, "++");
      } else if (peek_char() == '=') {
        advance();
        return make_token(TokenType::PLUSASSIGN, "+=");
      }
      return make_token(TokenType::PLUS, "+");

    case '-':
      if (peek_char() == '-') {
        advance();
        return make_token(TokenType::DECREMENT, "--");
      } else if (peek_char() == '=') {
        advance();
        return make_token(TokenType::MINUSASSIGN, "-=");
      } else if (peek_char() == '>') {
        advance();
        return make_token(TokenType::PTR, "->");
      }
      return make_token(TokenType::MINUS, "-");

    case '*':
      if (peek_char() == '=') {
        advance();
        return make_token(TokenType::MULASSIGN, "*=");
      }
      return make_token(TokenType::MUL, "*");

    case '/':
      if (peek_char() == '=') {
        advance();
        return make_token(TokenType::DIVASSIGN, "/=");
      }
      return make_token(TokenType::DIV, "/");

    case '%':
      if (peek_char() == '=') {
        advance();
        return make_token(TokenType::MODASSIGN, "%=");
      }
      return make_token(TokenType::MOD, "%");

    case '&':
      if (peek_char() == '&') {
        advance();
        return make_token(TokenType::LAND, "&&");
      } else if (peek_char() == '=') {
        advance();
        return make_token(TokenType::BANDASSIGN, "&=");
      }
      return make_token(TokenType::BAND, "&");

    case '|':
      if (peek_char() == '|') {
        advance();
        return make_token(TokenType::LOR, "||");
      } else if (peek_char() == '=') {
        advance();
        return make_token(TokenType::BORASSIGN, "|=");
      }
      return make_token(TokenType::BOR, "|");

    case '^':
      if (peek_char() == '=') {
        advance();
        return make_token(TokenType::BXORASSIGN, "^=");
      }
      return make_token(TokenType::BXOR, "^");

    case '!':
      if (peek_char() == '=') {
        advance();
        return make_token(TokenType::NE, "!=");
      }
      return make_token(TokenType::LNOT, "!");

    case '=':
      if (peek_char() == '=') {
        advance();
        return make_token(TokenType::EQ, "==");
      }
      return make_token(TokenType::ASSIGN, "=");

    case '<':
      if (peek_char() == '=') {
        advance();
        return make_token(TokenType::LE, "<=");
      } else if (peek_char() == '<') {
        advance();
        if (peek_char() == '=') {
          advance();
          return make_token(TokenType::LEFTASSIGN, "<<=");
        }
        return make_token(TokenType::LEFT, "<<");
      }
      return make_token(TokenType::LT, "<");

    case '>':
      if (peek_char() == '=') {
        advance();
        return make_token(TokenType::GE, ">=");
      } else if (peek_char() == '>') {
        advance();
        if (peek_char() == '=') {
          advance();
          return make_token(TokenType::RIGHTASSIGN, ">>=");
        }
        return make_token(TokenType::RIGHT, ">>");
      }
      return make_token(TokenType::GT, ">");

    default:
      return make_token(TokenType::INVALID, std::string(1, c));
  }
}

Token RecursiveDescentLexer::peek() {
  size_t saved_pos = pos_;
  size_t saved_line = line_;
  size_t saved_column = column_;

  Token tok = next();

  pos_ = saved_pos;
  line_ = saved_line;
  column_ = saved_column;

  return tok;
}

} // namespace bpftrace
