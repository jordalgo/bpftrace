# CMake integration for recursive descent parser
# Add this to src/CMakeLists.txt to build the recursive descent parser

# Option to enable recursive descent parser
option(USE_RECURSIVE_DESCENT_PARSER "Use recursive descent parser instead of Flex/Bison" OFF)

# Recursive descent parser sources
set(RD_PARSER_SOURCES
  rd_lexer.cpp
  rd_parser.cpp
  rd_driver.cpp
)

set(RD_PARSER_HEADERS
  rd_lexer.h
  rd_parser.h
  rd_driver.h
)

if(USE_RECURSIVE_DESCENT_PARSER)
  message(STATUS "Building with recursive descent parser")

  # Add recursive descent parser sources to the build
  target_sources(parser PRIVATE ${RD_PARSER_SOURCES})

  # Define a preprocessor macro to enable the RD parser
  target_compile_definitions(parser PRIVATE USE_RD_PARSER)

  # The recursive descent parser doesn't need Flex/Bison
  # So we can skip those dependencies
else()
  message(STATUS "Building with Flex/Bison parser (default)")

  # Use the existing Flex/Bison parser
  # (existing CMake configuration)
endif()

# Optional: Build the test program
option(BUILD_RD_PARSER_TEST "Build recursive descent parser test program" OFF)

if(BUILD_RD_PARSER_TEST)
  add_executable(rd_test
    rd_test.cpp
    ${RD_PARSER_SOURCES}
  )

  target_include_directories(rd_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/ast
  )

  target_link_libraries(rd_test
    # Add any required libraries here
  )
endif()

# Install headers if needed
if(USE_RECURSIVE_DESCENT_PARSER)
  install(FILES ${RD_PARSER_HEADERS}
    DESTINATION include/bpftrace
  )
endif()
