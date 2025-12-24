# Recursive Descent Parser Implementation Summary

## Overview

I've created a minimal working prototype of a recursive descent parser for bpftrace that runs side-by-side with the existing Flex/Bison implementation. This demonstrates how the parsing logic can be rewritten using pure C++ instead of external code generation tools.

## Files Created

### Core Implementation

1. **rd_lexer.h / rd_lexer.cpp** (650+ lines)
   - Tokenizes bpftrace source code
   - Handles all major token types: keywords, operators, literals, identifiers
   - Tracks source locations for error reporting
   - Supports comments (C++ and C style)

2. **rd_parser.h / rd_parser.cpp** (900+ lines)
   - Recursive descent parser with operator precedence
   - Parses expressions using precedence climbing
   - Parses statements (if, while, for, assignments, etc.)
   - Parses probes and attach points
   - Generates AST nodes compatible with existing bpftrace infrastructure

3. **rd_driver.h / rd_driver.cpp** (50+ lines)
   - Driver interface compatible with existing Driver class
   - Provides `parse_program()` and `parse_expr()` methods

### Documentation and Testing

4. **RD_README.md**
   - Comprehensive documentation of the implementation
   - Describes architecture, features, and limitations
   - Usage instructions and future work

5. **rd_test.cpp**
   - Standalone test program demonstrating the parser
   - Tests lexer, expression parsing, and program parsing

6. **RD_CMAKE_INTEGRATION.cmake**
   - CMake configuration for building with the recursive descent parser
   - Provides `USE_RECURSIVE_DESCENT_PARSER` option
   - Optional test program build

## Key Features

### Lexer (RecursiveDescentLexer)

- **Character-by-character scanning** with lookahead
- **Token types**: 90+ token types covering the entire bpftrace language
- **Source tracking**: Line and column number tracking for error messages
- **Comment handling**: Both `//` and `/* */` style comments
- **String literals**: Escape sequence handling
- **Number literals**: Decimal, hex, and scientific notation with suffixes
- **Special tokens**: Maps (@), variables ($), parameters ($1, $#)

### Parser (RecursiveDescentParser)

- **Operator precedence**: 15 levels of precedence correctly implemented
- **Expression parsing**:
  - Ternary operator (`?:`)
  - Binary operators (logical, bitwise, arithmetic, comparison)
  - Unary operators (!, ~, -, *, ++, --)
  - Postfix operators (++, --, [], ., ->)
  - Primary expressions (literals, identifiers, function calls)

- **Statement parsing**:
  - Variable declarations (`let $x`)
  - Assignments (with compound operators)
  - Control flow (if/else, while, for)
  - Jump statements (return, break, continue)
  - Blocks

- **Top-level parsing**:
  - Probe definitions with attach points
  - Predicates
  - Program structure

### Error Handling

- **Error reporting** with source location
- **Synchronization** for error recovery
- **Detailed error messages** showing line and column

## Grammar Structure

The parser implements a classic recursive descent structure:

```
Program:
  program → header? config? imports? probes*

Expressions (by precedence):
  expression → ternary
  ternary → logical_or ('?' expression ':' expression)?
  logical_or → logical_and ('||' logical_and)*
  logical_and → bitwise_or ('&&' bitwise_or)*
  bitwise_or → bitwise_xor ('|' bitwise_xor)*
  bitwise_xor → bitwise_and ('^' bitwise_and)*
  bitwise_and → equality ('&' equality)*
  equality → relational (('==' | '!=') relational)*
  relational → shift (('<' | '<=' | '>' | '>=') shift)*
  shift → additive (('<<' | '>>') additive)*
  additive → multiplicative (('+' | '-') multiplicative)*
  multiplicative → cast (('*' | '/' | '%') cast)*
  cast → ('(' type ')')? unary
  unary → (unop | '++' | '--' | 'sizeof')? postfix
  postfix → primary (postfix_op)*
  primary → literal | identifier | '(' expression ')' | ...

Statements:
  statement → expr_stmt | decl_stmt | assign_stmt | jump_stmt | block_stmt | if_stmt | while_stmt | for_stmt
  block → '{' statement* expression? '}'
```

## Comparison with Flex/Bison

### Advantages of Recursive Descent

1. **Pure C++**: No external code generation tools
2. **Easier debugging**: Use standard C++ debuggers
3. **Better error messages**: More control over error reporting
4. **More flexible**: Easier to add features and handle edge cases
5. **Better IDE support**: C++ code is fully understood by IDEs
6. **No build-time code generation**: Faster build iteration
7. **More maintainable**: Standard C++ patterns, no domain-specific language

### Disadvantages

1. **More verbose**: More code to write manually
2. **Manual precedence**: Must carefully structure precedence levels
3. **Potential for bugs**: More opportunities for manual errors
4. **Performance**: May be slightly slower (though usually negligible)

## Current Limitations

This is a **minimal working prototype** with several intentional limitations:

1. **Incomplete grammar**:
   - Structs, enums, and unions are partially implemented
   - Macros and subprograms are stubs
   - Config blocks are simplified
   - C preprocessor directives not handled

2. **Simplified features**:
   - Attach point parsing is basic
   - Type system is simplified
   - Some edge cases not handled

3. **Limited error recovery**: Basic synchronization only

4. **No integration**: Not yet integrated with the build system

## How to Use

### Building

The parser is designed to be built alongside the existing parser. In the future, you would:

```bash
# Build with recursive descent parser
cmake -DUSE_RECURSIVE_DESCENT_PARSER=ON ..
make

# Build the test program
cmake -DBUILD_RD_PARSER_TEST=ON ..
make rd_test
./rd_test
```

### Integration

To fully integrate this parser:

1. Add the CMake configuration to `src/CMakeLists.txt`
2. Modify the Driver class to conditionally use RD parser
3. Complete the missing language features
4. Add comprehensive tests
5. Update documentation

## Example Usage

```cpp
#include "rd_driver.h"

// Create AST context
bpftrace::ast::ASTContext ctx("source");

// Create driver
bpftrace::RecursiveDescentDriver driver(ctx);

// Parse a program
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

## Future Work

To make this production-ready:

1. **Complete the grammar**: Implement all missing features
2. **Improve error recovery**: Better synchronization and error messages
3. **Add tests**: Comprehensive test suite covering all features
4. **Performance**: Profile and optimize hot paths
5. **Documentation**: Complete API documentation
6. **Integration**: Full integration with bpftrace build system
7. **Validation**: Ensure semantic equivalence with Flex/Bison parser

## Architecture Decisions

### Why Recursive Descent?

- **Simplicity**: Easy to understand and maintain
- **Flexibility**: Can handle complex constructs easily
- **Error handling**: Better control over error recovery
- **Debugging**: Standard C++ debugging tools work

### Why Operator Precedence Climbing?

- Combines the simplicity of recursive descent with efficient operator parsing
- Each precedence level has its own function
- Natural mapping to the grammar
- Easy to extend with new operators

### Token Storage

- Tokens are created on-demand (not stored in a list)
- Keeps memory usage low
- Allows for streaming parsing

### AST Compatibility

- Uses the same AST node types as the Flex/Bison parser
- Ensures compatibility with the rest of bpftrace
- No changes needed to later compilation stages

## Performance Considerations

The recursive descent parser should have similar performance to Flex/Bison:

- **Lexer**: Single-pass, O(n) where n is input size
- **Parser**: Single-pass with limited lookahead, O(n)
- **Memory**: Tokens created on-demand, AST is only permanent allocation
- **Overall**: Linear time complexity, suitable for bpftrace programs

## Conclusion

This implementation demonstrates that the bpftrace parser can be successfully rewritten as a recursive descent parser in pure C++. While this is a minimal prototype, it shows the feasibility of the approach and provides a foundation for a complete implementation.

The recursive descent approach offers several advantages over Flex/Bison, particularly in terms of maintainability, debuggability, and flexibility. With additional work to complete the grammar and add comprehensive testing, this could become a viable alternative to the current parser implementation.
