# Quick Start Guide - Recursive Descent Parser

## What is this?

This is a **pure C++ recursive descent parser** that can replace the Flex/Bison parser in bpftrace. It's currently a working prototype that demonstrates the feasibility of the approach.

## Files Overview

```
src/
├── rd_lexer.h          # Lexer class definition
├── rd_lexer.cpp        # Lexer implementation
├── rd_parser.h         # Parser class definition
├── rd_parser.cpp       # Parser implementation
├── rd_driver.h         # Driver interface
├── rd_driver.cpp       # Driver implementation
├── rd_test.cpp         # Test program
└── RD_*.md            # Documentation
```

## How to Test (Without Building Full bpftrace)

Since this is a standalone implementation, you can test it independently:

### Quick Test

Create a simple test file:

```cpp
// test.cpp
#include "rd_lexer.h"
#include <iostream>

int main() {
  std::string source = "BEGIN { print(42); }";
  bpftrace::RecursiveDescentLexer lexer(source, &source);

  bpftrace::Token tok;
  do {
    tok = lexer.next();
    std::cout << "Token: " << tok.value << std::endl;
  } while (tok.type != bpftrace::TokenType::END);

  return 0;
}
```

Compile:
```bash
cd /data/users/jordalgo/bpftrace/src
g++ -std=c++20 -I. -I./ast -o test test.cpp rd_lexer.cpp
./test
```

## What Works

### ✅ Lexer
Tokenizes all bpftrace constructs:
```cpp
"42"          → INTEGER
"hello"       → STRING
"$var"        → VAR
"@map"        → MAP
"if"          → IF
"while"       → WHILE
"++"          → INCREMENT
"=="          → EQ
// etc.
```

### ✅ Parser
Parses expressions and statements:
```bpftrace
# Expressions
1 + 2 * 3
x ? y : z
func(a, b, c)
@map[key]

# Statements
let $x = 42;
if ($x > 0) { print($x); }
while ($i < 10) { $i++; }

# Probes
BEGIN { print("hello"); }
```

## Example Usage

### Parsing an Expression

```cpp
#include "rd_driver.h"

bpftrace::ast::ASTContext ctx("source");
bpftrace::RecursiveDescentDriver driver(ctx);

auto expr = driver.parse_expr("1 + 2 * 3");
if (expr.has_value()) {
  std::cout << "Parsed successfully!" << std::endl;
}
```

### Parsing a Program

```cpp
#include "rd_driver.h"

bpftrace::ast::ASTContext ctx("source");
bpftrace::RecursiveDescentDriver driver(ctx);

std::string program = R"(
  BEGIN {
    @count = 0;
  }

  tracepoint:syscalls:sys_enter_* {
    @count++;
  }
)";

auto *ast = driver.parse_program(program);
```

## Understanding the Code

### Lexer Structure

```cpp
class RecursiveDescentLexer {
  Token next();              // Get next token
  Token peek();              // Look ahead

private:
  Token scan_identifier();   // Scan identifier/keyword
  Token scan_number();       // Scan integer literal
  Token scan_string();       // Scan string literal
  void skip_whitespace();    // Skip whitespace/comments
};
```

### Parser Structure

```cpp
class RecursiveDescentParser {
  ast::Program *parse_program();    // Parse full program
  ast::Expression parse_expr();     // Parse expression

private:
  // Expression parsing (by precedence)
  ast::Expression expression();     // Top-level
  ast::Expression ternary();        // ? :
  ast::Expression logical_or();     // ||
  ast::Expression logical_and();    // &&
  ast::Expression equality();       // == !=
  ast::Expression relational();     // < <= > >=
  ast::Expression additive();       // + -
  ast::Expression multiplicative(); // * / %
  ast::Expression unary();          // ! ~ - ++ --
  ast::Expression postfix();        // [] . ->
  ast::Expression primary();        // literals, identifiers

  // Statement parsing
  ast::Statement statement();
  ast::Statement if_statement();
  ast::Statement while_statement();
  // etc.
};
```

## Debugging

One of the main advantages is **easy debugging**:

```bash
# Compile with debug symbols
g++ -g -std=c++20 -I. -o test test.cpp rd_lexer.cpp rd_parser.cpp

# Debug with gdb
gdb ./test

# Set breakpoints
(gdb) break RecursiveDescentParser::expression
(gdb) break RecursiveDescentLexer::scan_number
(gdb) run

# Step through code
(gdb) next
(gdb) step
(gdb) print current().value
```

## Common Patterns

### Adding a New Operator

1. **Add token type** (rd_lexer.h):
```cpp
enum class TokenType {
  // ... existing tokens
  MY_OPERATOR,
};
```

2. **Scan the operator** (rd_lexer.cpp):
```cpp
Token RecursiveDescentLexer::next() {
  // ...
  case '@':
    if (peek_char() == '@') {
      advance();
      return make_token(TokenType::MY_OPERATOR, "@@");
    }
    // ...
}
```

3. **Parse the operator** (rd_parser.cpp):
```cpp
ast::Expression RecursiveDescentParser::my_precedence_level() {
  auto expr = lower_precedence_level();

  while (match(TokenType::MY_OPERATOR)) {
    auto right = lower_precedence_level();
    expr = ctx_.make_node<ast::Binop>(loc, expr, Operator::MY_OP, right);
  }

  return expr;
}
```

### Adding a New Statement

1. **Add keyword** to lexer keywords map
2. **Add parsing function**:

```cpp
ast::Statement RecursiveDescentParser::my_statement() {
  consume(TokenType::MY_KEYWORD, "Expected 'my'");

  // Parse statement components
  auto expr = expression();

  consume(TokenType::SEMI, "Expected ';'");

  return ctx_.make_node<ast::MyStatement>(loc, expr);
}
```

3. **Call from statement()**:
```cpp
ast::Statement RecursiveDescentParser::statement() {
  if (check(TokenType::MY_KEYWORD)) {
    return my_statement();
  }
  // ... other cases
}
```

## Performance Tips

The parser is already efficient, but if you need to optimize:

1. **Token buffering**: Cache commonly accessed tokens
2. **String interning**: Reuse common string values
3. **Memory pooling**: Use arena allocation for AST nodes
4. **Reduced copying**: Use move semantics throughout

## Testing Strategy

### Unit Testing Lexer

```cpp
void test_lexer() {
  std::string source = "42 + 3";
  RecursiveDescentLexer lexer(source, &source);

  auto tok1 = lexer.next();
  assert(tok1.type == TokenType::INTEGER);
  assert(tok1.value == "42");

  auto tok2 = lexer.next();
  assert(tok2.type == TokenType::PLUS);

  auto tok3 = lexer.next();
  assert(tok3.type == TokenType::INTEGER);
  assert(tok3.value == "3");
}
```

### Unit Testing Parser

```cpp
void test_parser() {
  ast::ASTContext ctx("test");
  RecursiveDescentLexer lexer("1 + 2", &source);
  RecursiveDescentParser parser(ctx, lexer);

  auto expr = parser.parse_expr();
  assert(expr.has_value());

  // Verify it's a Binop with PLUS
  auto *binop = std::get_if<ast::Binop*>(&expr->value);
  assert(binop != nullptr);
  assert((*binop)->op == ast::Operator::PLUS);
}
```

## Common Issues

### Issue: "Expected ';' after expression"
**Cause**: Missing semicolon in input
**Fix**: Ensure all statements end with `;`

### Issue: Parse error at unexpected location
**Cause**: Lookahead needs adjustment
**Fix**: Check the precedence level and operator parsing

### Issue: Segmentation fault
**Cause**: Invalid AST node pointer
**Fix**: Ensure all AST nodes are created via `ctx_.make_node<>()`

## Limitations (Current Prototype)

This is a **minimal working prototype**, so:

- ❌ Structs/enums are incomplete
- ❌ Macros are stubs
- ❌ Config blocks are simplified
- ❌ Some edge cases not handled

**But these are not fundamental limitations** - they can all be implemented using the same patterns.

## Comparison with Flex/Bison

| What you want | Flex/Bison | Recursive Descent |
|---------------|-----------|-------------------|
| Easy debugging | ❌ | ✅ |
| Pure C++ | ❌ | ✅ |
| No external tools | ❌ | ✅ |
| Better errors | ❌ | ✅ |
| Less code | ✅ | ❌ |
| Automatic precedence | ✅ | ❌ |

## Next Steps

1. **Read** the documentation:
   - RD_README.md - Full documentation
   - RD_IMPLEMENTATION_SUMMARY.md - Technical details
   - RD_COMPARISON.md - Comparison with Flex/Bison

2. **Explore** the code:
   - rd_lexer.cpp - See how tokenization works
   - rd_parser.cpp - See how parsing works

3. **Experiment**:
   - Modify the lexer to recognize new tokens
   - Add a new operator to the parser
   - Improve error messages

4. **Extend**:
   - Implement missing features
   - Add more comprehensive error recovery
   - Optimize performance

## Get Help

If you need to understand:
- **How lexing works**: Read rd_lexer.cpp, start with `next()`
- **How parsing works**: Read rd_parser.cpp, start with `expression()`
- **How precedence works**: Follow the function call chain from `expression()` down
- **How to extend**: Look for similar features and follow the pattern

## Resources

- **Dragon Book**: Compilers: Principles, Techniques, and Tools
- **Crafting Interpreters**: https://craftinginterpreters.com/
- **C++ reference**: https://en.cppreference.com/

## Summary

This recursive descent parser is:
- ✅ Pure C++ (no external tools)
- ✅ Easy to debug
- ✅ Easy to extend
- ✅ Compatible with existing bpftrace AST
- ✅ A working prototype

It demonstrates that bpftrace can be successfully parsed without Flex/Bison, offering better maintainability and debuggability.

**Status**: Ready for experimentation and extension!
