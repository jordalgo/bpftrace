// Simple test program for the recursive descent parser
// This demonstrates basic functionality without requiring the full bpftrace build

#include <iostream>
#include <string>
#include "rd_lexer.h"
#include "rd_parser.h"
#include "rd_driver.h"

// Mock AST context for testing
class MockASTContext : public bpftrace::ast::ASTContext {
public:
  MockASTContext() : ASTContext("test_source") {}
};

void test_lexer() {
  std::cout << "=== Testing Lexer ===" << std::endl;

  std::string source = R"(
    BEGIN {
      $x = 42;
      @map[1] = $x + 10;
      if ($x > 0) {
        print("hello");
      }
    }
  )";

  bpftrace::RecursiveDescentLexer lexer(source, &source);

  std::cout << "Tokens:" << std::endl;
  bpftrace::Token tok;
  int count = 0;
  do {
    tok = lexer.next();
    if (tok.type != bpftrace::TokenType::END) {
      std::cout << "  [" << count++ << "] Type: " << static_cast<int>(tok.type)
                << ", Value: '" << tok.value << "'" << std::endl;
    }
  } while (tok.type != bpftrace::TokenType::END);

  std::cout << "Total tokens: " << count << std::endl << std::endl;
}

void test_expression_parser() {
  std::cout << "=== Testing Expression Parser ===" << std::endl;

  std::vector<std::string> expressions = {
    "42",
    "1 + 2",
    "x * y + z",
    "a == b && c != d",
    "x ? y : z",
    "@map[key]",
    "func(1, 2, 3)",
    "(a + b) * c",
  };

  MockASTContext ctx;

  for (const auto &expr_str : expressions) {
    std::cout << "Parsing: " << expr_str << std::endl;

    bpftrace::RecursiveDescentLexer lexer(expr_str, &expr_str);
    bpftrace::RecursiveDescentParser parser(ctx, lexer);

    try {
      auto expr = parser.parse_expr();
      if (expr.has_value()) {
        std::cout << "  ✓ Parsed successfully" << std::endl;
      } else {
        std::cout << "  ✗ Parse failed" << std::endl;
      }
    } catch (const std::exception &e) {
      std::cout << "  ✗ Exception: " << e.what() << std::endl;
    }
  }

  std::cout << std::endl;
}

void test_program_parser() {
  std::cout << "=== Testing Program Parser ===" << std::endl;

  std::string program = R"(
    BEGIN {
      $x = 0;
      while ($x < 10) {
        $x = $x + 1;
        print($x);
      }
    }
  )";

  std::cout << "Parsing program:" << std::endl;
  std::cout << program << std::endl;

  MockASTContext ctx;
  bpftrace::RecursiveDescentDriver driver(ctx, false);

  try {
    auto *ast = driver.parse_program(program);
    if (ast != nullptr) {
      std::cout << "✓ Program parsed successfully" << std::endl;
    } else {
      std::cout << "✗ Program parse failed" << std::endl;
    }
  } catch (const std::exception &e) {
    std::cout << "✗ Exception: " << e.what() << std::endl;
  }

  std::cout << std::endl;
}

int main() {
  std::cout << "Recursive Descent Parser Test" << std::endl;
  std::cout << "==============================" << std::endl << std::endl;

  test_lexer();
  test_expression_parser();
  test_program_parser();

  std::cout << "=== All tests completed ===" << std::endl;

  return 0;
}
