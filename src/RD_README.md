# Recursive Descent Parser for bpftrace

This directory contains a prototype recursive descent parser implementation for bpftrace, created as an alternative to the Flex/Bison-based parser.

## Files

- `rd_lexer.h` / `rd_lexer.cpp` - Recursive descent lexer
- `rd_parser.h` / `rd_parser.cpp` - Recursive descent parser
- `rd_driver.h` / `rd_driver.cpp` - Driver interface for the parser
- `rd_test.cpp` - Simple test program

## Building

The recursive descent parser is built alongside the original parser. To use it:

```bash
# Build the test program
g++ -std=c++20 -I../src -I../src/ast -o rd_test rd_test.cpp rd_lexer.cpp rd_parser.cpp rd_driver.cpp
```

## Architecture

### Lexer (RecursiveDescentLexer)

The lexer performs tokenization of the input source code. It:
- Scans characters sequentially
- Identifies tokens (keywords, identifiers, operators, literals)
- Tracks source locations (line and column numbers)
- Handles comments and whitespace

### Parser (RecursiveDescentParser)

The parser implements a top-down parsing strategy using recursive descent with operator precedence. The grammar is structured as:

```
program → attach_points predicate? block
expression → ternary
ternary → logical_or ('?' expression ':' expression)?
logical_or → logical_and ('||' logical_and)*
logical_and → bitwise_or ('&&' bitwise_or)*
...
primary → INTEGER | STRING | IDENTIFIER | MAP | VAR | '(' expression ')'
```

### Key Features

1. **Operator Precedence**: Correctly handles operator precedence through the recursive structure
2. **Error Recovery**: Includes basic error recovery via synchronization
3. **AST Generation**: Generates the same AST nodes as the original parser
4. **Source Locations**: Preserves accurate source location information for error reporting

## Current Limitations (Prototype)

This is a minimal working prototype and has several limitations:

1. **Incomplete Grammar**: Not all bpftrace language features are implemented
   - Missing: structs, enums, macros, subprograms
   - Simplified: config blocks, imports, attach point parsing

2. **Limited Error Recovery**: Basic synchronization, but could be improved

3. **No Preprocessor**: C preprocessor directives are not handled

4. **Backtracking**: Some constructs (like casts vs parenthesized expressions) need better lookahead

5. **Type System**: Type parsing is simplified

## Advantages over Flex/Bison

1. **Pure C++**: No external code generation tools needed
2. **Easier to Debug**: Standard C++ debugging tools work directly
3. **Better Error Messages**: Can provide more context-specific error messages
4. **More Flexible**: Easier to add language features without conflicts
5. **Better IDE Support**: C++ code is easier for IDEs to understand

## Testing

A simple test can be run with:

```bash
./rd_test
```

This will parse a simple bpftrace program and print the result.

## Integration

To integrate this parser into bpftrace:

1. Add the files to the build system (CMakeLists.txt)
2. Create a compilation flag to switch between parsers
3. Modify the driver interface to support both parsers
4. Complete the remaining language features
5. Add comprehensive tests

## Future Work

- Complete implementation of all language features
- Improve error recovery and error messages
- Add comprehensive test suite
- Performance optimization
- Integration with existing bpftrace infrastructure
