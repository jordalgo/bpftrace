#include "ast/ast.h"

#include <algorithm>

#include "ast/context.h"
#include "ast/visitor.h"
#include "log.h"

namespace bpftrace::ast {

static constexpr std::string_view ENUM = "enum ";

Integer::Integer(Diagnostics &d, int64_t n, location loc, bool is_negative)
    : Expression(d, loc), n(n), is_negative(is_negative)
{
  is_literal = true;
}

String::String(Diagnostics &d, const std::string &str, location loc)
    : Expression(d, loc), str(str)
{
  is_literal = true;
}

StackMode::StackMode(Diagnostics &d, const std::string &mode, location loc)
    : Expression(d, loc), mode(mode)
{
  is_literal = true;
}

Builtin::Builtin(Diagnostics &d, const std::string &ident, location loc)
    : Expression(d, loc), ident(is_deprecated(ident))
{
}

Identifier::Identifier(Diagnostics &d, const std::string &ident, location loc)
    : Expression(d, loc), ident(ident)
{
}

PositionalParameter::PositionalParameter(Diagnostics &d,
                                         PositionalParameterType ptype,
                                         long n,
                                         location loc)
    : Expression(d, loc), ptype(ptype), n(n)
{
  is_literal = true;
}

Call::Call(Diagnostics &d, const std::string &func, location loc)
    : Expression(d, loc), func(is_deprecated(func))
{
}

Call::Call(Diagnostics &d,
           const std::string &func,
           ExpressionList &&vargs,
           location loc)
    : Expression(d, loc), func(is_deprecated(func)), vargs(std::move(vargs))
{
}

Sizeof::Sizeof(Diagnostics &d, SizedType type, location loc)
    : Expression(d, loc), argtype(type)
{
}

Sizeof::Sizeof(Diagnostics &d, Expression *expr, location loc)
    : Expression(d, loc), expr(expr)
{
}

Offsetof::Offsetof(Diagnostics &d,
                   SizedType record,
                   std::vector<std::string> &field,
                   location loc)
    : Expression(d, loc), record(record), field(field)
{
}

Offsetof::Offsetof(Diagnostics &d,
                   Expression *expr,
                   std::vector<std::string> &field,
                   location loc)
    : Expression(d, loc), expr(expr), field(field)
{
}

Map::Map(Diagnostics &d, const std::string &ident, location loc)
    : Expression(d, loc), ident(ident)
{
  is_map = true;
}

Map::Map(Diagnostics &d,
         const std::string &ident,
         Expression &expr,
         location loc)
    : Expression(d, loc), ident(ident), key_expr(&expr)
{
  is_map = true;
  key_expr->key_for_map = this;
}

Variable::Variable(Diagnostics &d, const std::string &ident, location loc)
    : Expression(d, loc), ident(ident)
{
  is_variable = true;
}

Binop::Binop(Diagnostics &d,
             Expression *left,
             Operator op,
             Expression *right,
             location loc)
    : Expression(d, loc), left(left), right(right), op(op)
{
}

Unop::Unop(Diagnostics &d,
           Operator op,
           Expression *expr,
           bool is_post_op,
           location loc)
    : Expression(d, loc), expr(expr), op(op), is_post_op(is_post_op)
{
}

Ternary::Ternary(Diagnostics &d,
                 Expression *cond,
                 Expression *left,
                 Expression *right,
                 location loc)
    : Expression(d, loc), cond(cond), left(left), right(right)
{
}

FieldAccess::FieldAccess(Diagnostics &d,
                         Expression *expr,
                         const std::string &field,
                         location loc)
    : Expression(d, loc), expr(expr), field(field)
{
}

FieldAccess::FieldAccess(Diagnostics &d,
                         Expression *expr,
                         ssize_t index,
                         location loc)
    : Expression(d, loc), expr(expr), index(index)
{
}

ArrayAccess::ArrayAccess(Diagnostics &d,
                         Expression *expr,
                         Expression *indexpr,
                         location loc)
    : Expression(d, loc), expr(expr), indexpr(indexpr)
{
}

Cast::Cast(Diagnostics &d, SizedType cast_type, Expression *expr, location loc)
    : Expression(d, loc), expr(expr)
{
  type = cast_type;
}

Tuple::Tuple(Diagnostics &d, ExpressionList &&elems, location loc)
    : Expression(d, loc), elems(std::move(elems))
{
}

ExprStatement::ExprStatement(Diagnostics &d, Expression *expr, location loc)
    : Statement(d, loc), expr(expr)
{
}

AssignMapStatement::AssignMapStatement(Diagnostics &d,
                                       Map *map,
                                       Expression *expr,
                                       location loc)
    : Statement(d, loc), map(map), expr(expr)
{
  expr->map = map;
};

AssignVarStatement::AssignVarStatement(Diagnostics &d,
                                       Variable *var,
                                       Expression *expr,
                                       location loc)
    : Statement(d, loc), var(var), expr(expr)
{
  expr->var = var;
}

AssignVarStatement::AssignVarStatement(Diagnostics &d,
                                       VarDeclStatement *var_decl_stmt,
                                       Expression *expr,
                                       location loc)
    : Statement(d, loc),
      var_decl_stmt(var_decl_stmt),
      var(var_decl_stmt->var),
      expr(expr)
{
  expr->var = var;
}

AssignConfigVarStatement::AssignConfigVarStatement(
    Diagnostics &d,
    const std::string &config_var,
    Expression *expr,
    location loc)
    : Statement(d, loc), config_var(config_var), expr(expr)
{
}

VarDeclStatement::VarDeclStatement(Diagnostics &d,
                                   Variable *var,
                                   SizedType type,
                                   location loc)
    : Statement(d, loc), var(var), set_type(true)
{
  var->type = std::move(type);
}

VarDeclStatement::VarDeclStatement(Diagnostics &d, Variable *var, location loc)
    : Statement(d, loc), var(var)
{
  var->type = CreateNone();
}

Predicate::Predicate(Diagnostics &d, Expression *expr, location loc)
    : Node(d, loc), expr(expr)
{
}

AttachPoint::AttachPoint(Diagnostics &d,
                         const std::string &raw_input,
                         bool ignore_invalid,
                         location loc)
    : Node(d, loc), raw_input(raw_input), ignore_invalid(ignore_invalid)
{
}

Block::Block(Diagnostics &d, StatementList &&stmts, location loc)
    : Statement(d, loc), stmts(std::move(stmts))
{
}

If::If(Diagnostics &d,
       Expression *cond,
       Block *if_block,
       Block *else_block,
       location loc)
    : Statement(d, loc), cond(cond), if_block(if_block), else_block(else_block)
{
}

Unroll::Unroll(Diagnostics &d, Expression *expr, Block *block, location loc)
    : Statement(d, loc), expr(expr), block(block)
{
}

Probe::Probe(Diagnostics &d,
             AttachPointList &&attach_points,
             Predicate *pred,
             Block *block,
             location loc)
    : Node(d, loc),
      attach_points(std::move(attach_points)),
      pred(pred),
      block(block)
{
}

SubprogArg::SubprogArg(Diagnostics &d,
                       std::string name,
                       SizedType type,
                       location loc)
    : Node(d, loc), type(std::move(type)), name_(std::move(name))
{
}

std::string SubprogArg::name() const
{
  return name_;
}

Subprog::Subprog(Diagnostics &d,
                 std::string name,
                 SizedType return_type,
                 SubprogArgList &&args,
                 StatementList &&stmts,
                 location loc)
    : Node(d, loc),
      args(std::move(args)),
      return_type(std::move(return_type)),
      stmts(std::move(stmts)),
      name_(std::move(name))
{
}

Program::Program(Diagnostics &d,
                 const std::string &c_definitions,
                 Config *config,
                 ProbeList &&probes,
                 location loc)
    : Node(d, loc),
      c_definitions(c_definitions),
      config(config),
      probes(std::move(probes))
{
}

std::string opstr(const Jump &jump)
{
  switch (jump.ident) {
    case JumpType::RETURN:
      return "return";
    case JumpType::BREAK:
      return "break";
    case JumpType::CONTINUE:
      return "continue";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Binop &binop)
{
  switch (binop.op) {
    case Operator::EQ:
      return "==";
    case Operator::NE:
      return "!=";
    case Operator::LE:
      return "<=";
    case Operator::GE:
      return ">=";
    case Operator::LT:
      return "<";
    case Operator::GT:
      return ">";
    case Operator::LAND:
      return "&&";
    case Operator::LOR:
      return "||";
    case Operator::LEFT:
      return "<<";
    case Operator::RIGHT:
      return ">>";
    case Operator::PLUS:
      return "+";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "*";
    case Operator::DIV:
      return "/";
    case Operator::MOD:
      return "%";
    case Operator::BAND:
      return "&";
    case Operator::BOR:
      return "|";
    case Operator::BXOR:
      return "^";
    default:
      return {};
  }

  return {}; // unreached
}

std::string opstr(const Unop &unop)
{
  switch (unop.op) {
    case Operator::LNOT:
      return "!";
    case Operator::BNOT:
      return "~";
    case Operator::MINUS:
      return "-";
    case Operator::MUL:
      return "dereference";
    case Operator::INCREMENT:
      if (unop.is_post_op)
        return "++ (post)";
      return "++ (pre)";
    case Operator::DECREMENT:
      if (unop.is_post_op)
        return "-- (post)";
      return "-- (pre)";
    default:
      return {};
  }

  return {}; // unreached
}

AttachPoint &AttachPoint::create_expansion_copy(ASTContext &ctx,
                                                const std::string &match) const
{
  // Create a new node with the same raw tracepoint. We initialize all the
  // information about the attach point, and then override/reset values
  // depending on the specific probe type.
  auto &ap = *ctx.make_node<AttachPoint>(raw_input, ignore_invalid, loc);
  ap.index_ = index_;
  ap.provider = provider;
  ap.target = target;
  ap.lang = lang;
  ap.ns = ns;
  ap.func = func;
  ap.pin = pin;
  ap.usdt = usdt;
  ap.freq = freq;
  ap.len = len;
  ap.mode = mode;
  ap.async = async;
  ap.expansion = expansion;
  ap.address = address;
  ap.func_offset = func_offset;

  switch (probetype(ap.provider)) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
      ap.func = match;
      if (match.find(":") != std::string::npos)
        ap.target = erase_prefix(ap.func);
      break;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
      // Tracepoint, uprobe, and fentry/fexit probes specify both a target
      // (category for tracepoints, binary for uprobes, and kernel module
      // for fentry/fexit and a function name.
      ap.func = match;
      ap.target = erase_prefix(ap.func);
      break;
    case ProbeType::usdt:
      // USDT probes specify a target binary path, a provider, and a function
      // name.
      ap.func = match;
      ap.target = erase_prefix(ap.func);
      ap.ns = erase_prefix(ap.func);
      break;
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
      // Watchpoint probes come with target prefix. Strip the target to get the
      // function
      ap.func = match;
      erase_prefix(ap.func);
      break;
    case ProbeType::rawtracepoint:
      ap.func = match;
      break;
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::interval:
    case ProbeType::profile:
    case ProbeType::special:
    case ProbeType::iter:
    case ProbeType::invalid:
      break;
    default:
      LOG(BUG) << "Unknown probe type";
  }
  return ap;
}

std::string AttachPoint::name() const
{
  std::string n = provider;
  if (target != "")
    n += ":" + target;
  if (lang != "")
    n += ":" + lang;
  if (ns != "")
    n += ":" + ns;
  if (func != "") {
    n += ":" + func;
    if (func_offset != 0)
      n += "+" + std::to_string(func_offset);
  }
  if (address != 0)
    n += ":" + std::to_string(address);
  if (freq != 0)
    n += ":" + std::to_string(freq);
  if (len != 0)
    n += ":" + std::to_string(len);
  if (mode.size())
    n += ":" + mode;
  return n;
}

int AttachPoint::index() const
{
  return index_;
}

void AttachPoint::set_index(int index)
{
  index_ = index;
}

std::string Probe::name() const
{
  std::vector<std::string> ap_names;
  std::transform(attach_points.begin(),
                 attach_points.end(),
                 std::back_inserter(ap_names),
                 [](const AttachPoint *ap) { return ap->name(); });
  return str_join(ap_names, ",");
}

std::string Probe::args_typename() const
{
  return "struct " + name() + "_args";
}

int Probe::index() const
{
  return index_;
}

void Probe::set_index(int index)
{
  index_ = index;
}

std::string Subprog::name() const
{
  return name_;
}

bool Probe::has_ap_of_probetype(ProbeType probe_type)
{
  for (auto *ap : attach_points) {
    if (probetype(ap->provider) == probe_type)
      return true;
  }
  return false;
}

SizedType ident_to_record(const std::string &ident, int pointer_level)
{
  SizedType result = CreateRecord(ident, std::weak_ptr<Struct>());
  for (int i = 0; i < pointer_level; i++)
    result = CreatePointer(result);
  return result;
}

SizedType ident_to_sized_type(const std::string &ident)
{
  if (ident.starts_with(ENUM)) {
    auto enum_name = ident.substr(ENUM.size());
    // This is an automatic promotion to a uint64
    // even though it's possible that highest variant value of that enum
    // fits into a smaller int. This will also affect casts from a smaller
    // int and cause an ERROR: Integer size mismatch.
    // This could potentially be revisited or the cast relaxed
    // if we check the variant values during semantic analysis.
    return CreateEnum(64, enum_name);
  }
  return ident_to_record(ident);
}

} // namespace bpftrace::ast
