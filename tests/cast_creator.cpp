#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/args_resolver.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/builtins.h"
#include "ast/passes/c_macro_expansion.h"
#include "ast/passes/cast_creator.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/control_flow_analyser.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/import_scripts.h"
#include "ast/passes/loop_return.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/resolve_imports.h"
#include "ast/passes/type_graph.h"
#include "ast/passes/type_system.h"
#include "ast_matchers.h"
#include "bpftrace.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "struct.h"

namespace bpftrace::test::cast_creator {

using bpftrace::test::AssignMapStatement;
using bpftrace::test::AssignVarStatement;
using bpftrace::test::Binop;
using bpftrace::test::Block;
using bpftrace::test::Builtin;
using bpftrace::test::Cast;
using bpftrace::test::ExprStatement;
using bpftrace::test::FieldAccess;
using bpftrace::test::For;
using bpftrace::test::If;
using bpftrace::test::Integer;
using bpftrace::test::Map;
using bpftrace::test::MapAccess;
using bpftrace::test::NamedArgument;
using bpftrace::test::Probe;
using bpftrace::test::Program;
using bpftrace::test::Record;
using bpftrace::test::SizedType;
using bpftrace::test::String;
using bpftrace::test::Tuple;
using bpftrace::test::Typeof;
using bpftrace::test::VarDeclStatement;
using bpftrace::test::Variable;
using ::testing::_;
using ::testing::HasSubstr;

auto IntVar(const std::string &name, size_t size, bool is_signed = false)
{
  return Variable(name).WithType(
      SizedType(Type::integer).WithSize(size).WithSigned(is_signed));
}

struct Mock {
  BPFtrace &bpftrace;
};
enum class UnsafeMode {
  Enable = 0, // Default is safe.
};
enum class Child {
  Enable = 0, // Default is no child.
};
enum class NoFeatures {
  Enable = 0, // Default is full features.
};
struct Warning {
  std::string_view str;
};
struct NoWarning {
  std::string_view str;
};
struct Error {
  std::string_view str;
};
struct Types {
  ast::TypeMetadata &types;
};
struct ExpectedAST {
  ProgramMatcher matcher;
};

template <typename T, typename First, typename... Ts>
std::optional<T> extract(First &&arg, Ts &&...rest)
{
  if constexpr (std::is_same_v<std::decay_t<First>, T>) {
    // Assert that nothing in the rest matches T.
    static_assert(!(std::is_same_v<std::decay_t<Ts>, T> || ...),
                  "Only one argument of each type is allowed");
    return arg;
  }
  if constexpr (sizeof...(Ts) != 0) {
    return extract<T, Ts...>(std::forward<Ts>(rest)...);
  }
  return std::nullopt;
}

template <typename T>
std::optional<T> extract()
{
  return std::nullopt;
}

std::string_view clean_prefix(std::string_view view)
{
  while (!view.empty() && view[0] == '\n')
    view.remove_prefix(1); // Remove initial '\n'
  return view;
}

// This exists as a test fixture because the types may refer to `bpftrace`, so
// this objects lifetime must exceed the tests lifetime. This is easier with a
// fixture, and allows us to have a single harness.
class CastCreatorHarness {
public:
  template <typename... Ts>
    requires((std::is_same_v<std::decay_t<Ts>, Mock> ||
              std::is_same_v<std::decay_t<Ts>, UnsafeMode> ||
              std::is_same_v<std::decay_t<Ts>, Child> ||
              std::is_same_v<std::decay_t<Ts>, NoFeatures> ||
              std::is_same_v<std::decay_t<Ts>, Warning> ||
              std::is_same_v<std::decay_t<Ts>, NoWarning> ||
              std::is_same_v<std::decay_t<Ts>, Error> ||
              std::is_same_v<std::decay_t<Ts>, ExpectedAST> ||
              std::is_same_v<std::decay_t<Ts>, Types>) &&
             ...)
  ast::ASTContext test(std::string_view input, Ts &&...args)
  {
    ast::ASTContext ast("stdin", std::string(clean_prefix(input)));

    // Reset for each iteration. We only guarantee that the types remain
    // valid after the ASTContext has been returned.
    bpftrace_.reset();
    types_.reset();

    // Extract all extra arguments.
    auto mock = extract<Mock>(args...);
    auto unsafe_mode = extract<UnsafeMode>(args...);
    auto child = extract<Child>(args...);
    auto no_features = extract<NoFeatures>(args...);
    auto warning = extract<Warning>(args...);
    auto nowarning = extract<NoWarning>(args...);
    auto error = extract<Error>(args...);
    auto types = extract<Types>(args...);
    auto expected_ast = extract<ExpectedAST>(args...);

    if (!mock) {
      // Create a fresh instance.
      bpftrace_ = get_mock_bpftrace();
      mock.emplace(*bpftrace_);
    }
    mock->bpftrace.safe_mode_ = !unsafe_mode.has_value();
    mock->bpftrace.feature_ = std::make_unique<MockBPFfeature>(
        !no_features.has_value());
    if (child.has_value()) {
      mock->bpftrace.cmd_ = "not-empty"; // Used by TypeChecker.
    }
    if (!types) {
      types_.emplace();
      types.emplace(*types_);
    }

    auto ok = ast::PassManager()
                  .put(ast)
                  .put(mock->bpftrace)
                  .put(types->types)
                  .add(CreateParsePass())
                  .add(ast::CreateParseAttachpointsPass())
                  .add(ast::CreateMacroExpansionPass())
                  .add(ast::CreateFoldLiteralsPass())
                  .add(ast::CreateBuiltinsPass())
                  .add(ast::CreateMapSugarPass())
                  .add(ast::CreateTypeGraphPass())
                  .add(ast::CreateCastCreatorPass())
                  .run();
    EXPECT_TRUE(bool(ok));

    std::stringstream out;
    ast.diagnostics().emit(out, ast::Diagnostics::Severity::Warning);
    if (warning) {
      EXPECT_TRUE(!warning->str.empty());
      EXPECT_THAT(out.str(), HasSubstr(clean_prefix(warning->str)))
          << out.str();
    }
    if (nowarning) {
      EXPECT_TRUE(!nowarning->str.empty());
      EXPECT_THAT(out.str(), Not(HasSubstr(clean_prefix(nowarning->str))))
          << out.str();
    }
    out.str("");
    ast.diagnostics().emit(out, ast::Diagnostics::Severity::Error);
    const auto errstr = out.str();
    if (error) {
      if (!error->str.empty()) {
        EXPECT_THAT(errstr, HasSubstr(clean_prefix(error->str))) << errstr;
      } else {
        EXPECT_TRUE(!errstr.empty()) << errstr;
      }
    } else {
      EXPECT_EQ(errstr, "") << errstr;
    }
    out.str("");
    if (expected_ast) {
      EXPECT_THAT(ast, expected_ast->matcher);
    }

    return ast;
  }

private:
  std::unique_ptr<MockBPFtrace> bpftrace_;
  std::optional<ast::TypeMetadata> types_;
};

class CastCreatorTest : public CastCreatorHarness, public testing::Test {};

TEST_F(CastCreatorTest, variable_no_type)
{
  test(R"(begin { let $z; $a = 1; $b = typeinfo($z); })", Error{ R"(
stdin:1:13-15: ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
            ~~
stdin:1:39-41: ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
                                      ~~
stdin:1:25-27: ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
                        ~~
)" });

  test(R"(begin { let $a; let $b; $b = $a; $a = $b; })", Error{});
}

TEST_F(CastCreatorTest, variable_assignment)
{
  test(
      R"(begin { let $a: uint32 = (uint8)1; })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { AssignVarStatement(
              IntVar("$a", 4),
              Cast(Typeof(bpftrace::test::SizedType(Type::integer).WithSize(4)),
                   Cast(Typeof(bpftrace::test::SizedType(Type::integer)
                                   .WithSize(1)),
                        Integer(1)))) })) });
  test(R"(begin { let $a: uint32 = 1; })",
       ExpectedAST{ Program().WithProbe(
           Probe({ "begin" },
                 { AssignVarStatement(IntVar("$a", 4), Integer(1)) })) });

  test(R"(begin { $a = 1; $a = "str"; })", Error{ R"(
stdin:1:17-27: ERROR: Type mismatch for $a: trying to assign value of type 'string[4]' when variable already has a type 'uint8'
begin { $a = 1; $a = "str"; }
                ~~~~~~~~~~
)" });

  test(
      R"(begin { let $y; if (true) { $x = $y; if (true) { $x = "str"; } } else { $x = $y + 10; } $y = -1; })",
      Error{ R"(
stdin:1:29-36: ERROR: Type mismatch for $x: trying to assign value of type 'int8' when variable already has a type 'string[4]'
begin { let $y; if (true) { $x = $y; if (true) { $x = "str"; } } else { $x = $y + 10; } $y = -1; }
                            ~~~~~~~
)" });

  test(R"(begin { let $a: uint32 = -1; })", Error{});
  test(R"(begin { let $a: uint32 = (uint64)1; })", Error{});
  test(R"(begin { let $b; let $a: typeof($b) = (uint64)1; $b = (uint32)2; })",
       Error{});
  test(
      R"(begin {let $a; let $x: uint32 = (typeof($a))10; $a = (uint16)1; $a = (uint64)2;})",
      Error{});
  test(R"(begin { let $a: string[2] = "muchlongerstr"; })", Error{});
}

TEST_F(CastCreatorTest, comptime)
{
  test(
      R"(begin { let $c; if comptime (typeinfo($c).2 == "uint32") { $c = (uint64)2; } $c = (uint32)1; })",
      Error{ R"(
stdin:1:60-74: ERROR: Type mismatch for $c: trying to assign value of type 'uint64' when variable already has a type 'uint32'
begin { let $c; if comptime (typeinfo($c).2 == "uint32") { $c = (uint64)2; } $c = (uint32)1; }
                                                           ~~~~~~~~~~~~~~
)" });

  test(
      R"(begin { let $c; if comptime (typeinfo({ let $x = $c; $x }).2 == "uint32") { $c = (uint64)2; } $c = (uint32)1; })",
      Error{ R"(
stdin:1:77-91: ERROR: Type mismatch for $c: trying to assign value of type 'uint64' when variable already has a type 'uint32'
begin { let $c; if comptime (typeinfo({ let $x = $c; $x }).2 == "uint32") { $c = (uint64)2; } $c = (uint32)1; }
                                                                            ~~~~~~~~~~~~~~
)" });
}

} // namespace bpftrace::test::cast_creator
