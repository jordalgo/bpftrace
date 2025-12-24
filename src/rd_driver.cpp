#include "rd_driver.h"
#include <iostream>

namespace bpftrace {

ast::Program *RecursiveDescentDriver::parse_program(const std::string &source) {
  source_ref_ = &source;

  RecursiveDescentLexer lexer(source, source_ref_);
  RecursiveDescentParser parser(ctx, lexer);

  return parser.parse_program();
}

std::optional<ast::Expression> RecursiveDescentDriver::parse_expr(const std::string &source) {
  source_ref_ = &source;

  RecursiveDescentLexer lexer(source, source_ref_);
  RecursiveDescentParser parser(ctx, lexer);

  return parser.parse_expr();
}

void RecursiveDescentDriver::error(const ast::SourceLocation &l, const std::string &m) {
  std::cerr << "Error at line " << l.start.line << ", column " << l.start.column
            << ": " << m << std::endl;
}

} // namespace bpftrace
