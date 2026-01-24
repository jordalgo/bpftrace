#include "ast/passes/intrinsic_type_resolver.h"
#include "ast/ast.h"
#include "ast/async_event_types.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/map_sugar.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "config.h"
#include "config_parser.h"
#include "log.h"
#include "probe_types.h"
#include "struct.h"
#include "types.h"

#include <arpa/inet.h>

namespace bpftrace::ast {

namespace {

static std::unordered_set<std::string> VOID_RETURNING_FUNCS = {
  "join", "printf", "errorf", "warnf", "system", "cat",     "debugf",
  "exit", "print",  "clear",  "zero",  "time",   "unwatch", "fail"
};

} // namespace

IntrinsicTypeResolver::IntrinsicTypeResolver(BPFtrace &bpftrace,
                                             CDefinitions &c_definitions)
    : bpftrace_(bpftrace), c_definitions_(c_definitions)
{
}

void IntrinsicTypeResolver::visit(Probe &probe)
{
  top_level_node_ = &probe;
  visit(probe.attach_points);
  visit(probe.block);
}

void IntrinsicTypeResolver::visit(Builtin &builtin)
{
  builtin.builtin_type = CreateNone();
  if (builtin.ident == "ctx") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType pt = probetype(probe->attach_points[0]->provider);
    bpf_prog_type bt = progtype(pt);
    std::string func = probe->attach_points[0]->func;
    builtin.builtin_type = CreatePointer(CreateNone());
    switch (bt) {
      case BPF_PROG_TYPE_KPROBE: {
        auto record = bpftrace_.structs.Lookup("struct pt_regs");
        if (!record.expired()) {
          builtin.builtin_type = CreatePointer(
              CreateCStruct("struct pt_regs", record), AddrSpace::kernel);
          builtin.builtin_type.MarkCtxAccess();
        }
        break;
      }
      case BPF_PROG_TYPE_PERF_EVENT:
        builtin.builtin_type = CreatePointer(
            CreateCStruct("struct bpf_perf_event_data",
                          bpftrace_.structs.Lookup(
                              "struct bpf_perf_event_data")),
            AddrSpace::kernel);
        builtin.builtin_type.MarkCtxAccess();
        break;
      case BPF_PROG_TYPE_TRACING:
        if (pt == ProbeType::iter) {
          std::string type = "struct bpf_iter__" + func;
          builtin.builtin_type = CreatePointer(
              CreateCStruct(type, bpftrace_.structs.Lookup(type)),
              AddrSpace::kernel);
          builtin.builtin_type.MarkCtxAccess();
        }
        break;
      default:
        break;
    }
  } else if (builtin.ident == "pid" || builtin.ident == "tid") {
    builtin.builtin_type = CreateUInt32();
  } else if (builtin.ident == "nsecs" || builtin.ident == "__builtin_elapsed" ||
             builtin.ident == "__builtin_cgroup" ||
             builtin.ident == "__builtin_uid" ||
             builtin.ident == "__builtin_gid" ||
             builtin.ident == "__builtin_cpu" ||
             builtin.ident == "__builtin_rand" ||
             builtin.ident == "__builtin_jiffies" ||
             builtin.ident == "__builtin_ncpus") {
    builtin.builtin_type = CreateUInt64();
  } else if (builtin.ident == "__builtin_curtask") {
    builtin.builtin_type = CreatePointer(
        CreateCStruct("struct task_struct",
                      bpftrace_.structs.Lookup("struct task_struct")),
        AddrSpace::kernel);
  } else if (builtin.ident == "__builtin_retval") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType type = probe->get_probetype();
    if (type == ProbeType::fentry || type == ProbeType::fexit) {
      const auto *arg = bpftrace_.structs.GetProbeArg(*probe,
                                                      RETVAL_FIELD_NAME);
      if (arg) {
        builtin.builtin_type = arg->type;
      } else
        builtin.addError() << "Can't find a field " << RETVAL_FIELD_NAME;
    } else {
      builtin.builtin_type = CreateUInt64();
    }
    builtin.builtin_type.SetAS(find_addrspace(type));
  } else if (builtin.ident == "kstack") {
    if (bpftrace_.config_->stack_mode == StackMode::build_id) {
      builtin.addWarning() << "'build_id' stack mode can only be used for "
                              "ustack. Falling back to 'raw' mode.";
      builtin.builtin_type = CreateStack(true,
                                         StackType{ .mode = StackMode::raw });
    } else {
      builtin.builtin_type = CreateStack(
          true, StackType{ .mode = bpftrace_.config_->stack_mode });
    }
  } else if (builtin.ident == "ustack") {
    builtin.builtin_type = CreateStack(
        false, StackType{ .mode = bpftrace_.config_->stack_mode });
  } else if (builtin.ident == "__builtin_comm") {
    constexpr int COMM_SIZE = 16;
    builtin.builtin_type = CreateString(COMM_SIZE);
    builtin.builtin_type.SetAS(AddrSpace::kernel);
  } else if (builtin.ident == "__builtin_func") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType type = probe->get_probetype();
    if (type == ProbeType::uprobe || type == ProbeType::uretprobe) {
      builtin.builtin_type = CreateUSym();
    } else {
      builtin.builtin_type = CreateKSym();
    }
  } else if (builtin.is_argx()) {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    builtin.builtin_type = CreateUInt64();
    builtin.builtin_type.SetAS(
        find_addrspace(probetype(probe->attach_points[0]->provider)));
  } else if (builtin.ident == "__builtin_username") {
    builtin.builtin_type = CreateUsername();
  } else if (builtin.ident == "__builtin_usermode") {
    builtin.builtin_type = CreateUInt8();
  } else if (builtin.ident == "__builtin_cpid") {
    builtin.builtin_type = CreateUInt64();
  } else if (builtin.ident == "args") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;

    ProbeType type = probe->get_probetype();
    auto type_name = probe->args_typename();
    if (!type_name) {
      builtin.addError() << "Unable to resolve unique type name.";
      return;
    }

    if (type == ProbeType::fentry || type == ProbeType::fexit ||
        type == ProbeType::uprobe || type == ProbeType::rawtracepoint) {
      builtin.builtin_type = CreateCStruct(
          *type_name, bpftrace_.structs.Lookup(*type_name));
      if (builtin.builtin_type.GetFieldCount() == 0)
        builtin.addError() << "Cannot read function parameters";

      builtin.builtin_type.MarkCtxAccess();
      builtin.builtin_type.is_funcarg = true;
      builtin.builtin_type.SetAS(type == ProbeType::uprobe ? AddrSpace::user
                                                           : AddrSpace::kernel);
      if (type == ProbeType::uprobe)
        builtin.builtin_type.is_internal = true;
    } else if (type == ProbeType::tracepoint) {
      builtin.builtin_type = CreateCStruct(
          *type_name, bpftrace_.structs.Lookup(*type_name));
      builtin.builtin_type.SetAS(probe->attach_points.front()->target ==
                                         "syscalls"
                                     ? AddrSpace::user
                                     : AddrSpace::kernel);
      builtin.builtin_type.MarkCtxAccess();
    }
  } else {
    LOG(BUG) << "Unknown builtin variable: '" << builtin.ident << "'";
  }
}

void IntrinsicTypeResolver::visit(Identifier &identifier)
{
  if (c_definitions_.enums.contains(identifier.ident)) {
    const auto &enum_name = std::get<1>(c_definitions_.enums[identifier.ident]);
    identifier.ident_type = CreateEnum(64, enum_name);
  } else if (bpftrace_.structs.Has(identifier.ident)) {
    identifier.ident_type = CreateCStruct(
        identifier.ident, bpftrace_.structs.Lookup(identifier.ident));
  } else if (func_ == "nsecs") {
    identifier.ident_type = CreateTimestampMode();
    if (identifier.ident == "monotonic") {
      identifier.ident_type.ts_mode = TimestampMode::monotonic;
    } else if (identifier.ident == "boot") {
      identifier.ident_type.ts_mode = TimestampMode::boot;
    } else if (identifier.ident == "tai") {
      identifier.ident_type.ts_mode = TimestampMode::tai;
    } else if (identifier.ident == "sw_tai") {
      identifier.ident_type.ts_mode = TimestampMode::sw_tai;
    } else {
      identifier.addError() << "Invalid timestamp mode: " << identifier.ident;
    }
  } else {
    ConfigParser<StackMode> parser;
    StackMode mode;
    auto ok = parser.parse(func_, &mode, identifier.ident);
    if (ok) {
      identifier.ident_type = CreateStack(true, StackType{ .mode = mode });
    }
  }
}

void IntrinsicTypeResolver::visit(Call &call)
{
  // RAII setter for func_ context (used by Identifier resolution)
  struct func_setter {
    func_setter(IntrinsicTypeResolver &resolver, const std::string &s)
        : resolver_(resolver), old_func_(resolver_.func_)
    {
      resolver_.func_ = s;
    }

    ~func_setter()
    {
      resolver_.func_ = old_func_;
    }

  private:
    IntrinsicTypeResolver &resolver_;
    std::string old_func_;
  };

  func_setter scope_bound_func_setter{ *this, call.func };

  // Visit children so Builtins/Identifiers within vargs get resolved
  for (auto &varg : call.vargs) {
    visit(varg);
  }

  // Resolve the return type for known functions
  if (getAssignRewriteFuncs().contains(call.func) ||
      VOID_RETURNING_FUNCS.contains(call.func)) {
    call.return_type = CreateVoid();
  } else if (call.func == "str") {
    auto strlen = bpftrace_.config_->max_strlen;
    if (call.vargs.size() == 2) {
      if (auto *integer = call.vargs.at(1).as<Integer>()) {
        if (integer->value + 1 > strlen) {
          call.addWarning() << "length param (" << integer->value
                            << ") is too long and will be shortened to "
                            << strlen << " bytes (see BPFTRACE_MAX_STRLEN)";
        } else {
          strlen = integer->value + 1;
        }
      }

      if (auto *integer = dynamic_cast<NegativeInteger *>(
              call.vargs.at(1).as<NegativeInteger>())) {
        call.addError() << call.func << "cannot use negative length ("
                        << integer->value << ")";
      }
    }
    call.return_type = CreateString(strlen);
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "buf") {
    const uint64_t max_strlen = bpftrace_.config_->max_strlen;
    uint32_t max_buffer_size = max_strlen - sizeof(AsyncEvent::Buf);
    uint32_t buffer_size = max_buffer_size;

    if (call.vargs.size() == 1) {
      auto &arg = call.vargs.at(0);
      if (arg.type().IsArrayTy()) {
        buffer_size = arg.type().GetNumElements() *
                      arg.type().GetElementTy().GetSize();
      }
    } else if (call.vargs.size() == 2) {
      if (auto *integer = call.vargs.at(1).as<Integer>()) {
        buffer_size = integer->value;
      }
    }

    if (buffer_size > max_buffer_size) {
      buffer_size = max_buffer_size;
    }

    call.return_type = CreateBuffer(buffer_size);
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "ksym" || call.func == "usym") {
    if (call.func == "ksym")
      call.return_type = CreateKSym();
    else if (call.func == "usym")
      call.return_type = CreateUSym();
  } else if (call.func == "ntop") {
    int buffer_size = 24;
    call.return_type = CreateInet(buffer_size);
  } else if (call.func == "pton") {
    int af_type = 0, addr_size = 0;
    std::string addr;
    if (call.vargs.size() == 1) {
      if (auto *str = call.vargs.at(0).as<String>()) {
        addr = str->value;
        if (addr.find(".") != std::string::npos) {
          af_type = AF_INET;
          addr_size = 4;
        } else if (addr.find(":") != std::string::npos) {
          af_type = AF_INET6;
          addr_size = 16;
        } else {
          call.addError()
              << call.func
              << "() expects an string argument of an IPv4/IPv6 address, got "
              << addr;
          return;
        }
      } else {
        call.addError() << call.func << "() expects an string literal, got "
                        << call.vargs.at(0).type();
        return;
      }
    }

    std::vector<char> dst(addr_size);
    auto ret = inet_pton(af_type, addr.c_str(), dst.data());
    if (ret != 1) {
      call.addError() << call.func
                      << "() expects a valid IPv4/IPv6 address, got " << addr;
      return;
    }

    call.return_type = CreateArray(addr_size, CreateUInt8());
    call.return_type.SetAS(AddrSpace::kernel);
    call.return_type.is_internal = true;
  } else if (call.func == "reg") {
    call.return_type = CreateUInt64();
    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      ProbeType pt = probe->get_probetype();
      call.return_type.SetAS(find_addrspace(pt));
    } else {
      call.return_type.SetAS(AddrSpace::kernel);
    }
  } else if (call.func == "kaddr") {
    call.return_type = CreateUInt64();
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "percpu_kaddr") {
    call.return_type = CreateUInt64();
    call.return_type.SetAS(AddrSpace::kernel);
  } else if (call.func == "__builtin_uaddr") {
    auto *probe = get_probe(call, call.func);
    if (probe == nullptr)
      return;
    // Set default return type; detailed symbol resolution stays in TypeResolver
    call.return_type = CreatePointer(CreateInt(64), AddrSpace::user);
  } else if (call.func == "cgroupid") {
    call.return_type = CreateUInt64();
  } else if (call.func == "cgroup_path") {
    call.return_type = CreateCgroupPath();
  } else if (call.func == "stack_len") {
    call.return_type = CreateInt64();
  } else if (call.func == "strftime") {
    call.return_type = CreateTimestamp();
  } else if (call.func == "kstack") {
    check_stack_call(call, true);
  } else if (call.func == "ustack") {
    check_stack_call(call, false);
  } else if (call.func == "path") {
    auto call_type_size = bpftrace_.config_->max_strlen;
    if (call.vargs.size() == 2) {
      if (auto *size = call.vargs.at(1).as<Integer>()) {
        call_type_size = size->value;
      }
    }
    call.return_type = SizedType(Type::string, call_type_size);
  } else if (call.func == "strncmp") {
    call.return_type = CreateUInt64();
  } else if (call.func == "kptr" || call.func == "uptr") {
    auto as = (call.func == "kptr" ? AddrSpace::kernel : AddrSpace::user);
    call.return_type = call.vargs.front().type();
    call.return_type.SetAS(as);
  } else if (call.func == "macaddr") {
    call.return_type = CreateMacAddress();
  } else if (call.func == "bswap") {
    auto int_bit_width = 1;
    if (!call.vargs.empty()) {
      auto &arg = call.vargs.at(0);
      if (!arg.type().IsIntTy()) {
        call.addError() << call.func << "() only supports integer arguments ("
                        << arg.type().GetTy() << " provided)";
        return;
      }
      int_bit_width = arg.type().GetIntBitWidth();
    }
    call.return_type = CreateUInt(int_bit_width);
  } else if (call.func == "skboutput") {
    call.return_type = CreateUInt32();
  } else if (call.func == "nsecs") {
    call.return_type = CreateUInt64();
    call.return_type.ts_mode = TimestampMode::boot;
    if (call.vargs.size() == 1) {
      call.return_type.ts_mode = call.vargs.at(0).type().ts_mode;
    }
  } else if (call.func == "pid" || call.func == "tid") {
    call.return_type = CreateUInt32();
  } else if (call.func == "socket_cookie") {
    call.return_type = CreateUInt64();
  }
  // Unknown functions (e.g. BTF functions) are left for TypeResolver
}

void IntrinsicTypeResolver::check_stack_call(Call &call, bool kernel)
{
  call.return_type = CreateStack(kernel);
  StackType stack_type;
  stack_type.mode = bpftrace_.config_->stack_mode;

  switch (call.vargs.size()) {
    case 0:
      break;
    case 1: {
      if (auto *ident = call.vargs.at(0).as<Identifier>()) {
        ConfigParser<StackMode> parser;
        auto ok = parser.parse(call.func, &stack_type.mode, ident->ident);
        if (!ok) {
          ident->addError() << "Error parsing stack mode: " << ok.takeError();
        }
      } else if (auto *limit = call.vargs.at(0).as<Integer>()) {
        stack_type.limit = limit->value;
      } else {
        call.addError() << call.func << ": invalid limit value";
      }
      break;
    }
    case 2: {
      if (auto *ident = call.vargs.at(0).as<Identifier>()) {
        ConfigParser<StackMode> parser;
        auto ok = parser.parse(call.func, &stack_type.mode, ident->ident);
        if (!ok) {
          ident->addError() << "Error parsing stack mode: " << ok.takeError();
        }
      } else {
        call.addError() << "Expected stack mode as first argument";
      }
      if (auto *limit = call.vargs.at(1).as<Integer>()) {
        stack_type.limit = limit->value;
      } else {
        call.addError() << call.func << ": invalid limit value";
      }
      break;
    }
    default:
      call.addError() << "Invalid number of arguments";
      break;
  }
  constexpr int MAX_STACK_SIZE = 1024;
  if (stack_type.limit > MAX_STACK_SIZE) {
    call.addError() << call.func << "([int limit]): limit shouldn't exceed "
                    << MAX_STACK_SIZE << ", " << stack_type.limit << " given";
  }
  if (stack_type.mode == StackMode::build_id && kernel) {
    call.addError() << "'build_id' stack mode can only be used for ustack";
  }
  call.return_type = CreateStack(kernel, stack_type);
}

Probe *IntrinsicTypeResolver::get_probe(Node &node, std::string name)
{
  auto *probe = dynamic_cast<Probe *>(top_level_node_);
  if (probe == nullptr) {
    if (name.empty()) {
      node.addError() << "Feature not supported outside probe";
    } else {
      node.addError() << "Builtin " << name << " not supported outside probe";
    }
  }

  return probe;
}

AddrSpace IntrinsicTypeResolver::find_addrspace(ProbeType pt)
{
  switch (pt) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::iter:
    case ProbeType::rawtracepoint:
      return AddrSpace::kernel;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      return AddrSpace::user;
    case ProbeType::invalid:
    case ProbeType::special:
    case ProbeType::test:
    case ProbeType::benchmark:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::watchpoint:
      return AddrSpace::none;
  }
  return {}; // unreached
}

} // namespace bpftrace::ast
