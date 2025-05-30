#include <algorithm>
#include <arpa/inet.h>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <bcc/perf_reader.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <glob.h>
#include <iostream>
#include <ranges>
#include <regex>
#include <sstream>
#include <sys/epoll.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "ast/async_event_types.h"
#include "ast/context.h"
#include "async_action.h"
#include "bpfmap.h"
#include "bpfprogram.h"
#include "bpftrace.h"
#include "btf.h"
#include "log.h"
#include "printf.h"
#include "scopeguard.h"
#include "util/bpf_names.h"
#include "util/cgroup.h"
#include "util/cpus.h"
#include "util/exceptions.h"
#include "util/format.h"
#include "util/int_parser.h"
#include "util/kernel.h"
#include "util/paths.h"
#include "util/stats.h"
#include "util/system.h"
#include "util/wildcard.h"

namespace bpftrace {

std::set<DebugStage> bt_debug = {};
bool bt_quiet = false;
bool bt_verbose = false;
bool dry_run = false;
int BPFtrace::exit_code = 0;
volatile sig_atomic_t BPFtrace::exitsig_recv = false;
volatile sig_atomic_t BPFtrace::sigusr1_recv = false;

BPFtrace::~BPFtrace()
{
  close_pcaps();
}

Probe BPFtrace::generateWatchpointSetupProbe(const ast::AttachPoint &ap,
                                             const ast::Probe &probe)
{
  Probe setup_probe;
  setup_probe.name = util::get_watchpoint_setup_probe_name(ap.name());
  setup_probe.type = ProbeType::uprobe;
  setup_probe.path = ap.target;
  setup_probe.attach_point = ap.func;
  setup_probe.orig_name = util::get_watchpoint_setup_probe_name(probe.name());
  setup_probe.index = ap.index() > 0 ? ap.index() : probe.index();

  return setup_probe;
}

Probe BPFtrace::generate_probe(const ast::AttachPoint &ap,
                               const ast::Probe &p,
                               int usdt_location_idx)
{
  Probe probe;
  probe.path = ap.target;
  probe.attach_point = ap.func;
  probe.type = probetype(ap.provider);
  probe.log_size = config_->log_size;
  probe.orig_name = p.name();
  probe.ns = ap.ns;
  probe.name = ap.name();
  probe.need_expansion = p.need_expansion;
  probe.freq = ap.freq;
  probe.address = ap.address;
  probe.func_offset = ap.func_offset;
  probe.loc = 0;
  probe.usdt_location_idx = usdt_location_idx;
  probe.index = ap.index() ?: p.index();
  probe.len = ap.len;
  probe.mode = ap.mode;
  probe.async = ap.async;
  probe.pin = ap.pin;
  probe.is_session = ap.expansion == ast::ExpansionType::SESSION;
  return probe;
}

int BPFtrace::add_probe(ast::ASTContext &ctx,
                        const ast::AttachPoint &ap,
                        const ast::Probe &p,
                        int usdt_location_idx)
{
  auto type = probetype(ap.provider);
  auto probe = generate_probe(ap, p, usdt_location_idx);

  // Add the new probe(s) to resources
  if (ap.provider == "BEGIN" || ap.provider == "END" || ap.provider == "self") {
    // special probes
    auto target = ap.target.empty() ? "" : "_" + ap.target;
    auto name = ap.provider + target;
    resources.special_probes[name] = std::move(probe);
  } else if ((type == ProbeType::watchpoint ||
              type == ProbeType::asyncwatchpoint) &&
             !ap.func.empty()) {
    // (async)watchpoint - generate also the setup probe
    resources.probes.emplace_back(generateWatchpointSetupProbe(ap, p));
    resources.watchpoint_probes.emplace_back(std::move(probe));
  } else if (ap.expansion == ast::ExpansionType::MULTI ||
             ap.expansion == ast::ExpansionType::SESSION) {
    // (k|u)probe_(multi|session) - do expansion and set probe.funcs
    auto matches = probe_matcher_->get_matches_for_ap(ap);
    if (matches.empty())
      return 1;

    if (util::has_wildcard(ap.target)) {
      // If we have a wildcard in the target path, we need to generate one
      // probe per expanded target.
      assert(type == ProbeType::uprobe || type == ProbeType::uretprobe);
      std::unordered_map<std::string, Probe> target_map;
      for (const auto &func : matches) {
        ast::AttachPoint &match_ap = ap.create_expansion_copy(ctx, func);
        // Use the original (possibly wildcarded) function name
        match_ap.func = ap.func;
        auto found = target_map.find(match_ap.target);
        if (found != target_map.end()) {
          found->second.funcs.push_back(func);
        } else {
          auto probe = generate_probe(match_ap, p);
          probe.funcs.push_back(func);
          target_map.insert({ { match_ap.target, probe } });
        }
      }
      for (auto &pair : target_map) {
        resources.probes.push_back(std::move(pair.second));
      }
    } else {
      probe.funcs = std::vector<std::string>(matches.begin(), matches.end());
      resources.probes.push_back(std::move(probe));
    }
  } else {
    resources.probes.emplace_back(std::move(probe));
  }

  if (type == ProbeType::iter)
    has_iter_ = true;

  // Preload symbol tables if necessary
  if (resources.probes_using_usym.contains(&p) && util::is_exe(ap.target)) {
    usyms_.cache(ap.target);
  }

  return 0;
}

int BPFtrace::num_probes() const
{
  return resources.special_probes.size() + resources.probes.size();
}

void BPFtrace::request_finalize()
{
  finalize_ = true;
  attached_probes_.clear();
  if (child_)
    child_->terminate();
}

void perf_event_printer(void *cb_cookie, void *data, int size)
{
  // The perf event data is not aligned, so we use memcpy to copy the data and
  // avoid UBSAN errors. Using an std::vector guarantees that it will be aligned
  // to the largest type. See:
  // https://stackoverflow.com/questions/8456236/how-is-a-vectors-data-aligned.
  std::vector<uint8_t> data_aligned;
  data_aligned.resize(size);
  memcpy(data_aligned.data(), data, size);

  auto *bpftrace = static_cast<BPFtrace *>(cb_cookie);
  auto *arg_data = data_aligned.data();

  auto printf_id = AsyncAction(*reinterpret_cast<uint64_t *>(arg_data));

  int err;

  // Ignore the remaining events if perf_event_printer is called during
  // finalization stage (exit() builtin has been called)
  if (bpftrace->finalize_)
    return;

  if (bpftrace::BPFtrace::exitsig_recv) {
    bpftrace->request_finalize();
    return;
  }

  // async actions
  if (printf_id == AsyncAction::exit) {
    auto *exit = static_cast<AsyncEvent::Exit *>(data);
    BPFtrace::exit_code = exit->exit_code;
    bpftrace->request_finalize();
    return;
  } else if (printf_id == AsyncAction::print) {
    auto *print = static_cast<AsyncEvent::Print *>(data);
    const auto &map = bpftrace->bytecode_.getMap(print->mapid);

    err = bpftrace->print_map(map, print->top, print->div);

    if (err)
      LOG(BUG) << "Could not print map with ident \"" << map.name()
               << "\", err=" << std::to_string(err);
    return;
  } else if (printf_id == AsyncAction::print_non_map) {
    auto *print = static_cast<AsyncEvent::PrintNonMap *>(data);
    const SizedType &ty = bpftrace->resources.non_map_print_args.at(
        print->print_id);

    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < ty.GetSize(); ++i)
      bytes.emplace_back(print->content[i]);

    bpftrace->out_->value(*bpftrace, ty, bytes);

    return;
  } else if (printf_id == AsyncAction::clear) {
    auto *mapevent = static_cast<AsyncEvent::MapEvent *>(data);
    const auto &map = bpftrace->bytecode_.getMap(mapevent->mapid);

    err = bpftrace->clear_map(map);
    if (err)
      LOG(BUG) << "Could not clear map with ident \"" << map.name()
               << "\", err=" << std::to_string(err);
    return;
  } else if (printf_id == AsyncAction::zero) {
    auto *mapevent = static_cast<AsyncEvent::MapEvent *>(data);
    const auto &map = bpftrace->bytecode_.getMap(mapevent->mapid);

    err = bpftrace->zero_map(map);
    if (err)
      LOG(BUG) << "Could not zero map with ident \"" << map.name()
               << "\", err=" << std::to_string(err);
    return;
  } else if (printf_id == AsyncAction::time) {
    async_action::time_handler(bpftrace, data);
    return;
  } else if (printf_id == AsyncAction::join) {
    async_action::join_handler(bpftrace, data);
    return;
  } else if (printf_id == AsyncAction::helper_error) {
    async_action::helper_error_handler(bpftrace, data);
    return;
  } else if (printf_id == AsyncAction::watchpoint_attach) {
    bool abort = false;
    auto *watchpoint = static_cast<AsyncEvent::Watchpoint *>(data);
    uint64_t probe_idx = watchpoint->watchpoint_idx;
    uint64_t addr = watchpoint->addr;

    if (probe_idx >= bpftrace->resources.watchpoint_probes.size()) {
      LOG(ERROR) << "Invalid watchpoint probe idx=" << probe_idx;
      abort = true;
      goto out;
    }

    // Ignore duplicate watchpoints (idx && addr same), but allow the same
    // address to be watched by different probes.
    //
    // NB: this check works b/c we set Probe::addr below
    //
    // TODO: Should we be printing a warning or info message out here?
    if (bpftrace->resources.watchpoint_probes[probe_idx].address == addr)
      goto out;

    // Attach the real watchpoint probe
    {
      bool registers_available = true;
      Probe &wp_probe = bpftrace->resources.watchpoint_probes[probe_idx];
      wp_probe.address = addr;
      std::vector<std::unique_ptr<AttachedProbe>> aps;
      try {
        aps = bpftrace->attach_probe(wp_probe, bpftrace->bytecode_);
      } catch (const util::EnospcException &ex) {
        registers_available = false;
        bpftrace->out_->message(MessageType::lost_events,
                                "Failed to attach watchpoint probe. You are "
                                "out of watchpoint registers.");
        goto out;
      }

      if (aps.empty() && registers_available) {
        std::cerr << "Unable to attach real watchpoint probe" << std::endl;
        abort = true;
        goto out;
      }

      for (auto &ap : aps)
        bpftrace->attached_probes_.emplace_back(std::move(ap));
    }

  out:
    // Async watchpoints are not SIGSTOP'd
    if (bpftrace->resources.watchpoint_probes[probe_idx].async)
      return;

    // Let the tracee continue
    pid_t pid = bpftrace->child_
                    ? bpftrace->child_->pid()
                    : (bpftrace->procmon_ ? bpftrace->procmon_->pid() : -1);
    if (pid == -1 || ::kill(pid, SIGCONT) != 0) {
      std::cerr << "Failed to SIGCONT tracee: " << strerror(errno) << std::endl;
      abort = true;
    }

    if (abort)
      std::abort();

    return;
  } else if (printf_id == AsyncAction::watchpoint_detach) {
    auto *unwatch = static_cast<AsyncEvent::WatchpointUnwatch *>(data);
    uint64_t addr = unwatch->addr;

    // Remove all probes watching `addr`. Note how we fail silently here
    // (ie invalid addr). This lets script writers be a bit more aggressive
    // when unwatch'ing addresses, especially if they're sampling a portion
    // of addresses they're interested in watching.
    auto it = std::ranges::remove_if(bpftrace->attached_probes_,
                                     [&](const auto &ap) {
                                       return ap->probe().address == addr;
                                     });
    bpftrace->attached_probes_.erase(it.begin(), it.end());

    return;
  } else if (printf_id == AsyncAction::skboutput) {
    struct hdr_t {
      uint64_t aid;
      uint64_t id;
      uint64_t ns;
      uint8_t pkt[];
    } __attribute__((packed)) * hdr;

    hdr = static_cast<struct hdr_t *>(data);

    int offset = std::get<1>(bpftrace->resources.skboutput_args_.at(hdr->id));

    bpftrace->write_pcaps(
        hdr->id, hdr->ns, hdr->pkt + offset, size - sizeof(*hdr));
    return;
  } else if (printf_id >= AsyncAction::syscall &&
             printf_id <= AsyncAction::syscall_end) {
    async_action::syscall_handler(bpftrace, printf_id, arg_data);
    return;
  } else if (printf_id >= AsyncAction::cat &&
             printf_id <= AsyncAction::cat_end) {
    async_action::cat_handler(bpftrace, printf_id, arg_data);
    return;
  } else if (printf_id >= AsyncAction::printf &&
             printf_id <= AsyncAction::printf_end) {
    async_action::printf_handler(bpftrace, printf_id, arg_data);
    return;
  } else {
    LOG(BUG) << "Unknown printf_id: " << static_cast<int64_t>(printf_id);
  }
}

int ringbuf_printer(void *cb_cookie, void *data, size_t size)
{
  perf_event_printer(cb_cookie, data, size);
  return 0;
}

std::vector<std::unique_ptr<IPrintable>> BPFtrace::get_arg_values(
    const std::vector<Field> &args,
    uint8_t *arg_data)
{
  std::vector<std::unique_ptr<IPrintable>> arg_values;

  for (auto arg : args) {
    switch (arg.type.GetTy()) {
      case Type::integer:
        if (arg.type.IsSigned()) {
          int64_t val = 0;
          switch (arg.type.GetIntBitWidth()) {
            case 64:
              val = *reinterpret_cast<int64_t *>(arg_data + arg.offset);
              break;
            case 32:
              val = *reinterpret_cast<int32_t *>(arg_data + arg.offset);
              break;
            case 16:
              val = *reinterpret_cast<int16_t *>(arg_data + arg.offset);
              break;
            case 8:
              val = *reinterpret_cast<int8_t *>(arg_data + arg.offset);
              break;
            case 1:
              val = *reinterpret_cast<int8_t *>(arg_data + arg.offset);
              break;
            default:
              throw util::FatalUserException(
                  "get_arg_values: invalid integer size. "
                  "8, 4, 2 and byte supported. " +
                  std::to_string(arg.type.GetSize()) + "provided");
          }
          arg_values.push_back(std::make_unique<PrintableSInt>(val));
        } else {
          uint64_t val = 0;
          switch (arg.type.GetIntBitWidth()) {
            case 64:
              val = *reinterpret_cast<uint64_t *>(arg_data + arg.offset);
              break;
            case 32:
              val = *reinterpret_cast<uint32_t *>(arg_data + arg.offset);
              break;
            case 16:
              val = *reinterpret_cast<uint16_t *>(arg_data + arg.offset);
              break;
            case 8:
              val = *reinterpret_cast<uint8_t *>(arg_data + arg.offset);
              break;
            case 1:
              val = *reinterpret_cast<uint8_t *>(arg_data + arg.offset);
              break;
            default:
              throw util::FatalUserException(
                  "get_arg_values: invalid integer size. "
                  "8, 4, 2 and byte supported. " +
                  std::to_string(arg.type.GetSize()) + "provided");
          }

          // bpftrace represents enums as unsigned integers
          if (arg.type.IsEnumTy()) {
            auto enum_name = arg.type.GetName();
            if (enum_defs_.contains(enum_name) &&
                enum_defs_[enum_name].contains(val)) {
              arg_values.push_back(
                  std::make_unique<PrintableEnum>(val,
                                                  enum_defs_[enum_name][val]));
            } else {
              arg_values.push_back(
                  std::make_unique<PrintableEnum>(val, std::to_string(val)));
            }
          } else {
            arg_values.push_back(std::make_unique<PrintableInt>(val));
          }
        }
        break;
      case Type::string: {
        auto *p = reinterpret_cast<char *>(arg_data + arg.offset);
        arg_values.push_back(std::make_unique<PrintableString>(
            std::string(p, strnlen(p, arg.type.GetSize())),
            config_->max_strlen,
            config_->str_trunc_trailer.c_str()));
        break;
      }
      case Type::buffer: {
        auto length =
            reinterpret_cast<AsyncEvent::Buf *>(arg_data + arg.offset)->length;
        arg_values.push_back(std::make_unique<PrintableBuffer>(
            reinterpret_cast<AsyncEvent::Buf *>(arg_data + arg.offset)->content,
            length));
        break;
      }
      case Type::ksym_t:
        arg_values.push_back(std::make_unique<PrintableString>(resolve_ksym(
            *reinterpret_cast<uint64_t *>(arg_data + arg.offset))));
        break;
      case Type::usym_t:
        arg_values.push_back(std::make_unique<PrintableString>(resolve_usym(
            *reinterpret_cast<uint64_t *>(arg_data + arg.offset),
            *reinterpret_cast<int32_t *>(arg_data + arg.offset + 8),
            *reinterpret_cast<int32_t *>(arg_data + arg.offset + 12))));
        break;
      case Type::inet:
        arg_values.push_back(std::make_unique<PrintableString>(resolve_inet(
            *reinterpret_cast<int64_t *>(arg_data + arg.offset),
            reinterpret_cast<uint8_t *>(arg_data + arg.offset + 8))));
        break;
      case Type::username:
        arg_values.push_back(std::make_unique<PrintableString>(
            resolve_uid(*reinterpret_cast<uint64_t *>(arg_data + arg.offset))));
        break;
      case Type::kstack_t:
        arg_values.push_back(std::make_unique<PrintableString>(
            get_stack(*reinterpret_cast<int64_t *>(arg_data + arg.offset),
                      *reinterpret_cast<uint32_t *>(arg_data + arg.offset + 8),
                      -1,
                      -1,
                      false,
                      arg.type.stack_type,
                      8)));
        break;
      case Type::ustack_t:
        arg_values.push_back(std::make_unique<PrintableString>(
            get_stack(*reinterpret_cast<int64_t *>(arg_data + arg.offset),
                      *reinterpret_cast<uint32_t *>(arg_data + arg.offset + 8),
                      *reinterpret_cast<int32_t *>(arg_data + arg.offset + 16),
                      *reinterpret_cast<int32_t *>(arg_data + arg.offset + 20),
                      true,
                      arg.type.stack_type,
                      8)));
        break;
      case Type::timestamp:
        arg_values.push_back(
            std::make_unique<PrintableString>(resolve_timestamp(
                reinterpret_cast<AsyncEvent::Strftime *>(arg_data + arg.offset)
                    ->mode,
                reinterpret_cast<AsyncEvent::Strftime *>(arg_data + arg.offset)
                    ->strftime_id,
                reinterpret_cast<AsyncEvent::Strftime *>(arg_data + arg.offset)
                    ->nsecs)));
        break;
      case Type::pointer:
        arg_values.push_back(std::make_unique<PrintableInt>(
            *reinterpret_cast<uint64_t *>(arg_data + arg.offset)));
        break;
      case Type::mac_address:
        arg_values.push_back(
            std::make_unique<PrintableString>(resolve_mac_address(
                reinterpret_cast<uint8_t *>(arg_data + arg.offset))));
        break;
      case Type::cgroup_path_t:
        arg_values.push_back(std::make_unique<PrintableString>(
            resolve_cgroup_path(reinterpret_cast<AsyncEvent::CgroupPath *>(
                                    arg_data + arg.offset)
                                    ->cgroup_path_id,
                                reinterpret_cast<AsyncEvent::CgroupPath *>(
                                    arg_data + arg.offset)
                                    ->cgroup_id)));
        break;
      case Type::strerror_t:
        arg_values.push_back(std::make_unique<PrintableString>(
            strerror(*reinterpret_cast<uint64_t *>(arg_data + arg.offset))));
        break;
        // fall through
      default:
        LOG(BUG) << "invalid argument type";
    }
  }

  return arg_values;
}

void BPFtrace::add_param(const std::string &param)
{
  params_.emplace_back(param);
}

std::string BPFtrace::get_param(size_t i) const
{
  if (params_.size() < i) {
    return "";
  }
  return params_.at(i - 1);
}

size_t BPFtrace::num_params() const
{
  return params_.size();
}

void perf_event_lost(void *cb_cookie, uint64_t lost)
{
  auto *bpftrace = static_cast<BPFtrace *>(cb_cookie);
  bpftrace->out_->lost_events(lost);
}

std::vector<std::unique_ptr<AttachedProbe>> BPFtrace::attach_usdt_probe(
    Probe &probe,
    const BpfProgram &program,
    std::optional<int> pid,
    bool file_activation)
{
  std::vector<std::unique_ptr<AttachedProbe>> ret;

  if (feature_->has_uprobe_refcnt() || !file_activation || probe.path.empty()) {
    ret.emplace_back(
        std::make_unique<AttachedProbe>(probe, program, pid, *this));
    return ret;
  }

  // File activation works by scanning through /proc/*/maps and seeing
  // which processes have the target executable in their address space
  // with execute permission. If found, we will try to attach to each
  // process we find.
  //
  // Note that this is the slow path. If the kernel has semaphore support
  // (feature_->has_uprobe_refcnt()), the kernel can do this for us and
  // much faster too.
  glob_t globbuf;
  if (::glob("/proc/[0-9]*/maps", GLOB_NOSORT, nullptr, &globbuf))
    LOG(BUG) << "failed to glob";

  char *p;
  if (!(p = realpath(probe.path.c_str(), nullptr))) {
    LOG(ERROR) << "Failed to resolve " << probe.path;
    return ret;
  }
  std::string resolved(p);
  free(p);

  for (size_t i = 0; i < globbuf.gl_pathc; ++i) {
    std::string path(globbuf.gl_pathv[i]);
    std::ifstream file(path);
    if (file.fail()) {
      // The process could have exited between the glob and now. We have
      // to silently ignore that.
      continue;
    }

    std::string line;
    while (std::getline(file, line)) {
      if (line.find(resolved) == std::string::npos)
        continue;

      auto parts = util::split_string(line, ' ');
      if (parts.at(1).find('x') == std::string::npos)
        continue;

      // Remove `/proc/` prefix
      std::string pid_str(globbuf.gl_pathv[i] + 6);
      // No need to remove `/maps` suffix b/c stoi() will ignore trailing !ints

      int pid_parsed;
      try {
        pid_parsed = std::stoi(pid_str);
      } catch (const std::exception &ex) {
        throw util::FatalUserException("failed to parse pid=" + pid_str);
      }

      ret.emplace_back(
          std::make_unique<AttachedProbe>(probe, program, pid_parsed, *this));
      break;
    }
  }

  if (ret.empty())
    LOG(ERROR) << "Failed to find processes running " << probe.path;

  return ret;
}

std::vector<std::unique_ptr<AttachedProbe>> BPFtrace::attach_probe(
    Probe &probe,
    const BpfBytecode &bytecode)
{
  std::vector<std::unique_ptr<AttachedProbe>> ret;

  try {
    const auto &program = bytecode.getProgramForProbe(probe);
    std::optional<pid_t> pid = child_ ? std::make_optional(child_->pid())
                                      : this->pid();

    if (probe.type == ProbeType::usdt) {
      auto aps = attach_usdt_probe(probe, program, pid, usdt_file_activation_);
      for (auto &ap : aps)
        ret.emplace_back(std::move(ap));

      return ret;
    } else if (probe.type == ProbeType::uprobe ||
               probe.type == ProbeType::uretprobe) {
      ret.emplace_back(std::make_unique<AttachedProbe>(
          probe, program, pid, *this, safe_mode_));
      return ret;
    } else if (probe.type == ProbeType::watchpoint ||
               probe.type == ProbeType::asyncwatchpoint) {
      ret.emplace_back(
          std::make_unique<AttachedProbe>(probe, program, pid, *this));
      return ret;
    } else {
      ret.emplace_back(
          std::make_unique<AttachedProbe>(probe, program, pid, *this));
      return ret;
    }
  } catch (const util::EnospcException &e) {
    // Caller will handle
    throw e;
  } catch (const std::exception &e) {
    LOG(ERROR) << e.what();
    ret.clear();
  }
  return ret;
}

bool attach_reverse(const Probe &p)
{
  switch (p.type) {
    case ProbeType::special:
    case ProbeType::kprobe:
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
    case ProbeType::software:
    case ProbeType::fentry:
    case ProbeType::iter:
      return true;
    case ProbeType::fexit:
    case ProbeType::kretprobe:
    case ProbeType::tracepoint:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::watchpoint:
    case ProbeType::asyncwatchpoint:
    case ProbeType::hardware:
    case ProbeType::rawtracepoint:
      return false;
    case ProbeType::invalid:
      LOG(BUG) << "Unknown probe type";
  }

  return {}; // unreached
}

int BPFtrace::run_iter()
{
  auto probe = resources.probes.begin();
  char buf[1024] = {};
  ssize_t len;

  if (probe == resources.probes.end()) {
    LOG(ERROR) << "Failed to create iter probe";
    return 1;
  }

  // If a script contains an iter probe, it must be the only probe
  assert(attached_probes_.size() == 1);
  if (attached_probes_.empty()) {
    LOG(ERROR) << "Failed to attach iter probe";
    return 1;
  }

  auto &ap = *attached_probes_.begin();
  int link_fd = ap->linkfd_;
  if (link_fd < 0) {
    LOG(ERROR) << "Failed to link iter probe";
    return 1;
  }

  if (probe->pin.empty()) {
    int iter_fd = bpf_iter_create(link_fd);

    if (iter_fd < 0) {
      LOG(ERROR) << "Failed to open iter probe link";
      return 1;
    }

    while ((len = read(iter_fd, buf, sizeof(buf))) > 0) {
      fwrite(buf, len, 1, stdout);
    }

    close(iter_fd);
  } else {
    auto pin = probe->pin;

    if (pin.at(0) != '/')
      pin = "/sys/fs/bpf/" + pin;

    if (bpf_obj_pin(link_fd, pin.c_str()))
      LOG(ERROR) << "Failed to pin iter probe link";
    else
      std::cout << "Program pinned to " << pin << std::endl;
  }

  return 0;
}

int BPFtrace::prerun() const
{
  uint64_t num_probes = this->num_probes();
  const auto max_probes = config_->max_probes;
  if (num_probes == 0) {
    if (!bt_quiet)
      std::cout << "No probes to attach" << std::endl;
    return 1;
  } else if (num_probes > max_probes) {
    LOG(ERROR)
        << "Can't attach to " << num_probes << " probes because it "
        << "exceeds the current limit of " << max_probes << " probes.\n"
        << "You can increase the limit through the BPFTRACE_MAX_PROBES "
        << "environment variable, but BE CAREFUL since a high number of probes "
        << "attached can cause your system to crash.";
    return 1;
  } else if (!bt_quiet)
    out_->attached_probes(num_probes);

  return 0;
}

int BPFtrace::run(BpfBytecode bytecode)
{
  int err = prerun();
  if (err)
    return err;

  bytecode_ = std::move(bytecode);
  bytecode_.set_map_ids(resources);
  bytecode_.update_global_vars(*this);

  try {
    bytecode_.load_progs(resources, *btf_, *feature_, *config_);
  } catch (const HelperVerifierError &e) {
    // To provide the most useful diagnostics, provide the error for every
    // callsite. After all, they all must be fixed.
    for (const auto &info : helper_use_loc_[e.func_id]) {
      LOG(ERROR,
          std::string(info.source_location),
          std::vector(info.source_context))
          << e.what();
    }
    return -1;
  } catch (const std::runtime_error &e) {
    LOG(ERROR) << e.what();
    return -1;
  }

  err = setup_output();
  if (err)
    return err;
  SCOPE_EXIT
  {
    teardown_output();
  };

  err = create_pcaps();
  if (err) {
    LOG(ERROR) << "Failed to create pcap file(s)";
    return err;
  }

  if (bytecode_.hasMap(MapType::Elapsed)) {
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    auto nsec = (1000000000ULL * ts.tv_sec) + ts.tv_nsec;
    uint64_t key = 0;

    if (bpf_update_elem(
            bytecode_.getMap(MapType::Elapsed).fd(), &key, &nsec, 0) < 0) {
      perror("Failed to write start time to elapsed map");
      return -1;
    }
  }

  auto begin_probe = resources.special_probes.find("BEGIN");
  if (begin_probe != resources.special_probes.end()) {
    auto &begin_prog = bytecode_.getProgramForProbe((*begin_probe).second);
    if (::bpf_prog_test_run_opts(begin_prog.fd(), nullptr))
      return -1;

    LOG(V1) << "Attaching BEGIN";
  }

  auto signal_probe = resources.special_probes.find("self_signal");
  if (signal_probe != resources.special_probes.end()) {
    auto &sig_prog = bytecode_.getProgramForProbe((*signal_probe).second);
    sigusr1_prog_fd_ = sig_prog.fd();
  }

  if (child_ && has_usdt_) {
    try {
      child_->run(true);
    } catch (const std::exception &e) {
      LOG(ERROR) << "Failed to setup child: " << e.what();
      return -1;
    }
  }

  // The kernel appears to fire some probes in the order that they were
  // attached and others in reverse order. In order to make sure that blocks
  // are executed in the same order they were declared, iterate over the probes
  // twice: in the first pass iterate forward and attach the probes that will
  // be fired in the same order they were attached, and in the second pass
  // iterate in reverse and attach the rest.
  for (auto &probe : resources.probes) {
    if (BPFtrace::exitsig_recv) {
      request_finalize();
      return -1;
    }
    if (!attach_reverse(probe)) {
      auto aps = attach_probe(probe, bytecode_);

      if (aps.empty())
        return -1;

      for (auto &ap : aps)
        attached_probes_.emplace_back(std::move(ap));
    }
  }

  for (auto &probe : std::ranges::reverse_view(resources.probes)) {
    if (BPFtrace::exitsig_recv) {
      request_finalize();
      return -1;
    }
    if (attach_reverse(probe)) {
      auto aps = attach_probe(probe, bytecode_);

      if (aps.empty())
        return -1;

      for (auto &ap : aps)
        attached_probes_.emplace_back(std::move(ap));
    }
  }

  if (dry_run) {
    request_finalize();
    return 0;
  }

  // Kick the child to execute the command.
  if (child_) {
    try {
      if (has_usdt_)
        child_->resume();
      else
        child_->run();
    } catch (const std::exception &e) {
      LOG(ERROR) << "Failed to run child: " << e.what();
      return -1;
    }
  }

  // Used by runtime test framework to know when to run AFTER directive
  if (std::getenv("__BPFTRACE_NOTIFY_PROBES_ATTACHED"))
    std::cout << "__BPFTRACE_NOTIFY_PROBES_ATTACHED" << std::endl;

#ifdef HAVE_LIBSYSTEMD
  err = sd_notify(false, "READY=1\nSTATUS=Processing events...");
  if (err < 0)
    LOG(WARNING) << "Failed to send readiness notification, ignoring: "
                 << strerror(-err);
#endif

  if (has_iter_) {
    int err = run_iter();
    if (err)
      return err;
  } else {
    poll_output();
  }

#ifdef HAVE_LIBSYSTEMD
  err = sd_notify(false, "STOPPING=1\nSTATUS=Shutting down...");
  if (err < 0)
    LOG(WARNING) << "Failed to send shutdown notification, ignoring: "
                 << strerror(-err);
#endif

  attached_probes_.clear();
  // finalize_ and exitsig_recv should be false from now on otherwise
  // perf_event_printer() can ignore the `END` events.
  finalize_ = false;
  exitsig_recv = false;

  auto end_probe = resources.special_probes.find("END");
  if (end_probe != resources.special_probes.end()) {
    auto &end_prog = bytecode_.getProgramForProbe((*end_probe).second);
    if (::bpf_prog_test_run_opts(end_prog.fd(), nullptr))
      return -1;

    LOG(V1) << "Attaching END";
  }

  poll_output(/* drain */ true);

  return 0;
}

int BPFtrace::setup_output()
{
  if (is_ringbuf_enabled()) {
    setup_ringbuf();
  }
  int err = setup_event_loss();
  if (err)
    return err;
  if (is_perf_event_enabled()) {
    return setup_perf_events();
  }
  return 0;
}

int BPFtrace::setup_perf_events()
{
  epollfd_ = epoll_create1(EPOLL_CLOEXEC);
  if (epollfd_ == -1) {
    LOG(ERROR) << "Failed to create epollfd";
    return -1;
  }

  std::vector<int> cpus = util::get_online_cpus();
  online_cpus_ = cpus.size();
  for (int cpu : cpus) {
    void *reader = bpf_open_perf_buffer(&perf_event_printer,
                                        &perf_event_lost,
                                        this,
                                        -1,
                                        cpu,
                                        config_->perf_rb_pages);
    if (reader == nullptr) {
      LOG(ERROR) << "Failed to open perf buffer";
      return -1;
    }
    // Store the perf buffer pointers in a vector of unique_ptrs.
    // When open_perf_buffers_ is cleared or destroyed,
    // perf_reader_free is automatically called.
    open_perf_buffers_.emplace_back(reader, perf_reader_free);

    struct epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.ptr = reader;
    int reader_fd = perf_reader_fd(static_cast<perf_reader *>(reader));

    bpf_update_elem(
        bytecode_.getMap(MapType::PerfEvent).fd(), &cpu, &reader_fd, 0);
    if (epoll_ctl(epollfd_, EPOLL_CTL_ADD, reader_fd, &ev) == -1) {
      LOG(ERROR) << "Failed to add perf reader to epoll";
      return -1;
    }
  }
  return 0;
}

void BPFtrace::setup_ringbuf()
{
  ringbuf_ = ring_buffer__new(
      bytecode_.getMap(MapType::Ringbuf).fd(), ringbuf_printer, this, nullptr);
}

int BPFtrace::setup_event_loss()
{
  if (bpf_update_elem(bytecode_.getMap(MapType::EventLossCounter).fd(),
                      const_cast<uint32_t *>(&event_loss_cnt_key_),
                      const_cast<uint64_t *>(&event_loss_cnt_val_),
                      0)) {
    LOG(ERROR) << "fail to init event loss counter";
    return -1;
  }
  return 0;
}

void BPFtrace::teardown_output()
{
  if (is_ringbuf_enabled())
    ring_buffer__free(ringbuf_);

  if (is_perf_event_enabled())
    // Calls perf_reader_free() on all open perf buffers.
    open_perf_buffers_.clear();
}

void BPFtrace::poll_output(bool drain)
{
  int ready;
  bool do_poll_perf_event = is_perf_event_enabled();
  bool do_poll_ringbuf = is_ringbuf_enabled();
  auto should_retry = [](int ready) {
    // epoll_wait will set errno to EINTR if an interrupt received, it is
    // retryable if not caused by SIGINT. ring_buffer__poll does not set errno,
    // we will keep retrying till SIGINT.
    return ready < 0 && (errno == 0 || errno == EINTR) &&
           !BPFtrace::exitsig_recv;
  };
  auto should_stop = [this, drain](int ready) {
    // Stop if either
    //   * an exit signal is received
    //   * epoll_wait has encountered an error (eg signal delivery)
    //   * there's no events left and we've been instructed to drain or
    //     finalization has been requested through exit() builtin.
    return BPFtrace::exitsig_recv || ready < 0 ||
           (ready == 0 && (drain || finalize_));
  };

  if (do_poll_perf_event && epollfd_ < 0) {
    LOG(ERROR) << "Invalid epollfd " << epollfd_;
    return;
  }

  while (true) {
    if (do_poll_perf_event) {
      ready = poll_perf_events();
      if (should_retry(ready)) {
        if (!do_poll_ringbuf)
          continue;
      }
      if (should_stop(ready)) {
        do_poll_perf_event = false;
      }
    }

    // print loss events
    handle_event_loss();

    if (do_poll_ringbuf) {
      ready = ring_buffer__poll(ringbuf_, timeout_ms);
      if (should_retry(ready)) {
        continue;
      }
      if (should_stop(ready)) {
        do_poll_ringbuf = false;
      }
    }
    if (!do_poll_perf_event && !do_poll_ringbuf) {
      return;
    }

    // If we are tracing a specific pid and it has exited, we should exit
    // as well b/c otherwise we'd be tracing nothing.
    if ((procmon_ && !procmon_->is_alive()) ||
        (child_ && !child_->is_alive())) {
      return;
    }

    if (BPFtrace::sigusr1_recv) {
      BPFtrace::sigusr1_recv = false;

      if (sigusr1_prog_fd_.has_value()) {
        if (::bpf_prog_test_run_opts(*sigusr1_prog_fd_, nullptr)) {
          LOG(ERROR) << "Failed to run signal probe";
          return;
        }
        LOG(V1) << "Attaching self:signal";
      }
    }
  }
}

int BPFtrace::poll_perf_events()
{
  auto events = std::vector<struct epoll_event>(online_cpus_);
  int ready = epoll_wait(epollfd_, events.data(), online_cpus_, timeout_ms);
  if (ready <= 0) {
    return ready;
  }
  for (int i = 0; i < ready; i++) {
    perf_reader_event_read(static_cast<perf_reader *>(events[i].data.ptr));
  }
  return ready;
}

void BPFtrace::handle_event_loss()
{
  uint64_t current_value = 0;
  if (bpf_lookup_elem(bytecode_.getMap(MapType::EventLossCounter).fd(),
                      const_cast<uint32_t *>(&event_loss_cnt_key_),
                      &current_value)) {
    LOG(ERROR) << "fail to get event loss counter";
  }
  if (current_value) {
    if (current_value > event_loss_count_) {
      out_->lost_events(current_value - event_loss_count_);
      event_loss_count_ = current_value;
    } else if (current_value < event_loss_count_) {
      LOG(ERROR) << "Invalid event loss count value: " << current_value
                 << ", last seen: " << event_loss_count_;
    }
  }
}

int BPFtrace::print_maps()
{
  if (dry_run)
    return 0;

  for (const auto &map : bytecode_.maps()) {
    if (!map.second.is_printable())
      continue;

    int err = print_map(map.second, 0, 0);
    if (err)
      return err;
  }

  return 0;
}

// clear a map
int BPFtrace::clear_map(const BpfMap &map)
{
  if (!map.is_clearable())
    return zero_map(map);

  uint8_t *old_key = nullptr;
  auto key = std::vector<uint8_t>(map.key_size());

  // snapshot keys, then operate on them
  std::vector<std::vector<uint8_t>> keys;
  while (bpf_get_next_key(map.fd(), old_key, key.data()) == 0) {
    keys.push_back(key);
    old_key = key.data();
  }

  for (auto &k : keys) {
    int err = bpf_delete_elem(map.fd(), k.data());
    if (err && err != -ENOENT) {
      LOG(ERROR) << "failed to look up elem: " << err;
      return -1;
    }
  }

  return 0;
}

// zero a map
int BPFtrace::zero_map(const BpfMap &map)
{
  uint64_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;

  uint8_t *old_key = nullptr;
  auto key = std::vector<uint8_t>(map.key_size());

  // snapshot keys, then operate on them
  std::vector<std::vector<uint8_t>> keys;
  while (bpf_get_next_key(map.fd(), old_key, key.data()) == 0) {
    keys.push_back(key);
    old_key = key.data();
  }

  int value_size = map.value_size() * nvalues;
  std::vector<uint8_t> zero(value_size, 0);
  for (auto &k : keys) {
    int err = bpf_update_elem(map.fd(), k.data(), zero.data(), BPF_EXIST);

    if (err && err != -ENOENT) {
      LOG(ERROR) << "failed to look up elem: " << err;
      return -1;
    }
  }

  return 0;
}

int BPFtrace::print_map(const BpfMap &map, uint32_t top, uint32_t div)
{
  const auto &map_info = resources.maps_info.at(map.name());
  const auto &value_type = map_info.value_type;
  if (value_type.IsHistTy() || value_type.IsLhistTy())
    return print_map_hist(map, top, div);

  uint64_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;

  uint8_t *old_key = nullptr;
  auto key = std::vector<uint8_t>(map.key_size());

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key;

  while (bpf_get_next_key(map.fd(), old_key, key.data()) == 0) {
    auto value = std::vector<uint8_t>(map.value_size() * nvalues);
    int err = bpf_lookup_elem(map.fd(), key.data(), value.data());
    if (err == -ENOENT) {
      // key was removed by the eBPF program during bpf_get_next_key() and
      // bpf_lookup_elem(), let's skip this key
      continue;
    } else if (err) {
      LOG(ERROR) << "failed to look up elem: " << err;
      return -1;
    }

    values_by_key.emplace_back(key, value);

    old_key = key.data();
  }

  if (value_type.IsCountTy() || value_type.IsSumTy() || value_type.IsIntTy()) {
    bool is_signed = value_type.IsSigned();
    std::ranges::sort(values_by_key,

                      [&](auto &a, auto &b) {
                        if (is_signed)
                          return util::reduce_value<int64_t>(a.second,
                                                             nvalues) <
                                 util::reduce_value<int64_t>(b.second, nvalues);
                        return util::reduce_value<uint64_t>(a.second, nvalues) <
                               util::reduce_value<uint64_t>(b.second, nvalues);
                      });
  } else if (value_type.IsMinTy() || value_type.IsMaxTy()) {
    std::ranges::sort(values_by_key,

                      [&](auto &a, auto &b) {
                        return util::min_max_value<uint64_t>(
                                   a.second, nvalues, value_type.IsMaxTy()) <
                               util::min_max_value<uint64_t>(
                                   b.second, nvalues, value_type.IsMaxTy());
                      });
  } else if (value_type.IsAvgTy() || value_type.IsStatsTy()) {
    if (value_type.IsSigned()) {
      std::ranges::sort(values_by_key,

                        [&](auto &a, auto &b) {
                          return util::avg_value<int64_t>(a.second, nvalues) <
                                 util::avg_value<int64_t>(b.second, nvalues);
                        });
    } else {
      std::ranges::sort(values_by_key,

                        [&](auto &a, auto &b) {
                          return util::avg_value<uint64_t>(a.second, nvalues) <
                                 util::avg_value<uint64_t>(b.second, nvalues);
                        });
    }
  } else {
    sort_by_key(map_info.key_type, values_by_key);
  };

  if (div == 0)
    div = 1;

  if (value_type.IsAvgTy() || value_type.IsStatsTy()) {
    out_->map_stats(*this, map, top, div, values_by_key);
    return 0;
  }

  out_->map(*this, map, top, div, values_by_key);
  return 0;
}

int BPFtrace::print_map_hist(const BpfMap &map, uint32_t top, uint32_t div)
{
  // A hist-map adds an extra 8 bytes onto the end of its key for storing
  // the bucket number.
  // e.g. A map defined as: @x[1, 2] = @hist(3);
  // would actually be stored with the key: [1, 2, 3]

  uint64_t nvalues = map.is_per_cpu_type() ? ncpus_ : 1;

  uint8_t *old_key = nullptr;
  auto key = std::vector<uint8_t>(map.key_size());

  std::map<std::vector<uint8_t>, std::vector<uint64_t>> values_by_key;

  const auto &map_info = resources.maps_info.at(map.name());
  while (bpf_get_next_key(map.fd(), old_key, key.data()) == 0) {
    auto key_prefix = std::vector<uint8_t>(map_info.key_type.GetSize());
    auto bucket = util::read_data<uint64_t>(key.data() +
                                            map_info.key_type.GetSize());

    for (size_t i = 0; i < map_info.key_type.GetSize(); i++)
      key_prefix.at(i) = key.at(i);

    auto value = std::vector<uint8_t>(map.value_size() * nvalues);
    int err = bpf_lookup_elem(map.fd(), key.data(), value.data());
    if (err == -ENOENT) {
      // key was removed by the eBPF program during bpf_get_next_key() and
      // bpf_lookup_elem(), let's skip this key
      continue;
    } else if (err) {
      LOG(ERROR) << "failed to look up elem: " << err;
      return -1;
    }

    if (!values_by_key.contains(key_prefix)) {
      // New key - create a list of buckets for it
      if (map_info.value_type.IsHistTy())
        values_by_key[key_prefix] = std::vector<uint64_t>(65 * 32);
      else
        values_by_key[key_prefix] = std::vector<uint64_t>(1002);
    }
    values_by_key[key_prefix].at(
        bucket) = util::reduce_value<uint64_t>(value, nvalues);

    old_key = key.data();
  }

  // Sort based on sum of counts in all buckets
  std::vector<std::pair<std::vector<uint8_t>, uint64_t>> total_counts_by_key;
  for (auto &map_elem : values_by_key) {
    int64_t sum = 0;
    for (unsigned long i : map_elem.second) {
      sum += i;
    }
    total_counts_by_key.emplace_back(map_elem.first, sum);
  }
  std::ranges::sort(total_counts_by_key,

                    [&](auto &a, auto &b) { return a.second < b.second; });

  if (div == 0)
    div = 1;
  out_->map_hist(*this, map, top, div, values_by_key, total_counts_by_key);
  return 0;
}

std::optional<std::string> BPFtrace::get_watchpoint_binary_path() const
{
  if (child_) {
    // We can ignore all error checking here b/c child.cpp:validate_cmd() has
    // already done it
    auto args = util::split_string(cmd_, ' ', /* remove_empty */ true);
    assert(!args.empty());
    return util::resolve_binary_path(args[0]).front();
  } else if (pid().has_value())
    return "/proc/" + std::to_string(pid().value_or(0)) + "/exe";
  else {
    return std::nullopt;
  }
}

std::string BPFtrace::get_stack(int64_t stackid,
                                uint32_t nr_stack_frames,
                                int32_t pid,
                                int32_t probe_id,
                                bool ustack,
                                StackType stack_type,
                                int indent)
{
  struct stack_key stack_key = { .stackid = stackid,
                                 .nr_stack_frames = nr_stack_frames };
  auto stack_trace = std::vector<uint64_t>(stack_type.limit);
  int err = bpf_lookup_elem(bytecode_.getMap(stack_type.name()).fd(),
                            &stack_key,
                            stack_trace.data());
  if (err) {
    // ignore EFAULT errors: eg, kstack used but no kernel stack
    LOG(ERROR) << "failed to look up stack id: " << stackid
               << " stack length: " << nr_stack_frames << " (pid " << pid
               << "): " << err;
    return "";
  }

  std::ostringstream stack;
  std::string padding(indent, ' ');

  stack << "\n";
  for (uint32_t i = 0; i < nr_stack_frames;) {
    uint64_t addr = stack_trace.at(i);
    if (stack_type.mode == StackMode::raw) {
      stack << std::hex << addr << std::endl;
      ++i;
      continue;
    }
    std::vector<std::string> syms;
    if (!ustack)
      syms = resolve_ksym_stack(addr,
                                true,
                                stack_type.mode == StackMode::perf,
                                config_->show_debug_info);
    else
      syms = resolve_usym_stack(addr,
                                pid,
                                probe_id,
                                true,
                                stack_type.mode == StackMode::perf,
                                config_->show_debug_info);

    std::string sym;
    for (size_t sym_idx = 0; i < nr_stack_frames && sym_idx < syms.size();) {
      sym = syms.at(sym_idx);
      switch (stack_type.mode) {
        case StackMode::bpftrace:
          stack << padding << sym << std::endl;
          break;
        case StackMode::perf:
          stack << "\t" << std::hex << addr << std::dec << " " << sym
                << std::endl;
          break;
        case StackMode::raw:
          LOG(BUG) << "StackMode::raw should have been processed before "
                      "symbolication.";
          break;
      }
      ++i;
      ++sym_idx;
    }
  }

  return stack.str();
}

std::string BPFtrace::resolve_uid(uint64_t addr) const
{
  std::string file_name = "/etc/passwd";
  std::string uid = std::to_string(addr);
  std::string username;

  std::ifstream file(file_name);
  if (file.fail()) {
    LOG(ERROR) << strerror(errno) << ": " << file_name;
    return username;
  }

  std::string line;
  bool found = false;

  while (std::getline(file, line) && !found) {
    auto fields = util::split_string(line, ':');

    if (fields.size() >= 3 && fields[2] == uid) {
      found = true;
      username = fields[0];
    }
  }

  file.close();

  return username;
}

std::string BPFtrace::resolve_timestamp(uint32_t mode,
                                        uint32_t strftime_id,
                                        uint64_t nsecs)
{
  static const auto usec_regex = std::regex("%f");
  static constexpr auto ns_in_sec = 1'000'000'000;
  auto ts_mode = static_cast<TimestampMode>(mode);
  struct timespec zero = {};
  struct timespec *basetime = &zero;

  if (ts_mode == TimestampMode::boot) {
    if (!boottime_) {
      LOG(ERROR)
          << "Cannot resolve timestamp due to failed boot time calculation";
      return "(?)";
    } else {
      basetime = &boottime_.value();
    }
  }

  // Calculate and localize timestamp
  struct tm tmp;
  time_t time = basetime->tv_sec + ((basetime->tv_nsec + nsecs) / ns_in_sec);
  if (!localtime_r(&time, &tmp)) {
    LOG(ERROR) << "localtime_r: " << strerror(errno);
    return "(?)";
  }

  // Process strftime() format string extensions
  const auto &raw_fmt = resources.strftime_args[strftime_id];
  uint64_t us = ((basetime->tv_nsec + nsecs) % ns_in_sec) / 1000;
  char usecs_buf[7];
  snprintf(usecs_buf, sizeof(usecs_buf), "%06" PRIu64, us);
  auto fmt = std::regex_replace(raw_fmt, usec_regex, usecs_buf);

  const auto timestr_size = config_->max_strlen;
  std::string timestr(timestr_size, '\0');
  size_t timestr_len = strftime(
      timestr.data(), timestr_size, fmt.c_str(), &tmp);
  if (timestr_len == 0) {
    LOG(ERROR) << "strftime returned 0";
    return "(?)";
  }

  // Fit return value to formatted length
  timestr.resize(timestr_len);
  return timestr;
}

std::string BPFtrace::resolve_buf(const char *buf, size_t size)
{
  return util::hex_format_buffer(buf, size);
}

std::string BPFtrace::resolve_ksym(uint64_t addr)
{
  auto syms = resolve_ksym_stack(addr, false, false, false);
  assert(syms.size() == 1);
  return syms.front();
}

std::vector<std::string> BPFtrace::resolve_ksym_stack(uint64_t addr,
                                                      bool show_offset,
                                                      bool perf_mode,
                                                      bool show_debug_info)
{
  return ksyms_.resolve(addr, show_offset, perf_mode, show_debug_info);
}

uint64_t BPFtrace::resolve_kname(const std::string &name) const
{
  uint64_t addr = 0;
  std::string file_name = "/proc/kallsyms";

  std::ifstream file(file_name);
  if (file.fail()) {
    LOG(ERROR) << strerror(errno) << ": " << file_name;
    return addr;
  }

  std::string line;

  while (std::getline(file, line) && addr == 0) {
    auto tokens = util::split_string(line, ' ');

    if (name == tokens[2]) {
      addr = read_address_from_output(line);
      break;
    }
  }

  file.close();

  return addr;
}

static int sym_resolve_callback(const char *name,
                                uint64_t addr,
                                uint64_t size,
                                void *payload)
{
  auto *sym = static_cast<struct symbol *>(payload);
  if (!strcmp(name, sym->name.c_str())) {
    sym->address = addr;
    sym->size = size;
    return -1;
  }
  return 0;
}

int BPFtrace::resolve_uname(const std::string &name,
                            struct symbol *sym,
                            const std::string &path) const
{
  sym->name = name;
  struct bcc_symbol_option option;
  memset(&option, 0, sizeof(option));
  option.use_symbol_type = (1 << STT_OBJECT | 1 << STT_FUNC |
                            1 << STT_GNU_IFUNC);

  return bcc_elf_foreach_sym(path.c_str(), sym_resolve_callback, &option, sym);
}

std::string BPFtrace::resolve_mac_address(const uint8_t *mac_addr) const
{
  const size_t SIZE = 18;
  char addr[SIZE];
  snprintf(addr,
           SIZE,
           "%02X:%02X:%02X:%02X:%02X:%02X",
           mac_addr[0],
           mac_addr[1],
           mac_addr[2],
           mac_addr[3],
           mac_addr[4],
           mac_addr[5]);
  return addr;
}

std::string BPFtrace::resolve_cgroup_path(uint64_t cgroup_path_id,
                                          uint64_t cgroup_id) const
{
  auto paths = util::get_cgroup_paths(
      cgroup_id, resources.cgroup_path_args[cgroup_path_id]);
  std::stringstream result;
  for (auto &pair : paths) {
    if (pair.second.empty())
      continue;
    result << pair.first << ":" << pair.second << ",";
  }
  return result.str().substr(0, result.str().size() - 1);
}

uint64_t BPFtrace::read_address_from_output(std::string output)
{
  std::string first_word = output.substr(0, output.find(" "));
  return std::stoull(first_word, nullptr, 16);
}

static std::string resolve_inetv4(const uint8_t *inet)
{
  char addr_cstr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, inet, addr_cstr, INET_ADDRSTRLEN);
  return addr_cstr;
}

static std::string resolve_inetv6(const uint8_t *inet)
{
  char addr_cstr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, inet, addr_cstr, INET6_ADDRSTRLEN);
  return addr_cstr;
}

std::string BPFtrace::resolve_inet(int af, const uint8_t *inet) const
{
  std::string addrstr;
  switch (af) {
    case AF_INET:
      addrstr = resolve_inetv4(inet);
      break;
    case AF_INET6:
      addrstr = resolve_inetv6(inet);
      break;
  }

  // TODO(mmarchini): handle inet_ntop errors
  return addrstr;
}

std::string BPFtrace::resolve_usym(uint64_t addr, int32_t pid, int32_t probe_id)
{
  auto syms = resolve_usym_stack(addr, pid, probe_id, false, false, false);
  assert(syms.size() == 1);
  return syms.front();
}

std::vector<std::string> BPFtrace::resolve_usym_stack(uint64_t addr,
                                                      int32_t pid,
                                                      int32_t probe_id,
                                                      bool show_offset,
                                                      bool perf_mode,
                                                      bool show_debug_info)
{
  std::string pid_exe = util::get_pid_exe(pid);
  if (pid_exe.empty() && probe_id != -1) {
    // sometimes program cannot be determined from PID, typically when the
    // process does not exist anymore; in that case, try to get program name
    // from probe
    // note: this fails if the probe contains a wildcard, since the probe id
    // is not generated per match
    auto probe_full = resolve_probe(probe_id);
    if (probe_full.find(',') == std::string::npos &&
        !util::has_wildcard(probe_full)) {
      // only find program name for probes that contain one program name,
      // to avoid incorrect symbol resolutions
      size_t start = probe_full.find(':') + 1;
      size_t end = probe_full.find(':', start);
      pid_exe = probe_full.substr(start, end - start);
    }
  }
  return usyms_.resolve(
      addr, pid, pid_exe, show_offset, perf_mode, show_debug_info);
}

std::string BPFtrace::resolve_probe(uint64_t probe_id) const
{
  assert(probe_id < resources.probe_ids.size());
  return resources.probe_ids[probe_id];
}

void BPFtrace::sort_by_key(
    const SizedType &key,
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key)
{
  if (key.IsTupleTy()) {
    // Sort the key arguments in reverse order so the results are sorted by
    // the first argument first, then the second, etc.
    auto &fields = key.GetFields();
    for (size_t i = key.GetFieldCount(); i-- > 0;) {
      const auto &field = fields.at(i);
      if (field.type.IsIntTy()) {
        if (field.type.GetSize() == 8) {
          std::ranges::stable_sort(values_by_key,

                                   [&](auto &a, auto &b) {
                                     auto va = util::read_data<uint64_t>(
                                         a.first.data() + field.offset);
                                     auto vb = util::read_data<uint64_t>(
                                         b.first.data() + field.offset);
                                     return va < vb;
                                   });
        } else if (field.type.GetSize() == 4) {
          std::ranges::stable_sort(values_by_key,

                                   [&](auto &a, auto &b) {
                                     auto va = util::read_data<uint32_t>(
                                         a.first.data() + field.offset);
                                     auto vb = util::read_data<uint32_t>(
                                         b.first.data() + field.offset);
                                     return va < vb;
                                   });
        } else {
          LOG(BUG) << "invalid integer argument size. 4 or 8  expected, but "
                   << field.type.GetSize() << " provided";
        }
      } else if (field.type.IsStringTy()) {
        std::ranges::stable_sort(
            values_by_key,

            [&](auto &a, auto &b) {
              return strncmp(reinterpret_cast<const char *>(a.first.data() +
                                                            field.offset),
                             reinterpret_cast<const char *>(b.first.data() +
                                                            field.offset),
                             field.type.GetSize()) < 0;
            });
      }
    }
  } else if (key.IsIntTy()) {
    if (key.GetSize() == 8) {
      std::ranges::stable_sort(
          values_by_key,

          [&](auto &a, auto &b) {
            auto va = util::read_data<uint64_t>(a.first.data());
            auto vb = util::read_data<uint64_t>(b.first.data());
            return va < vb;
          });
    } else if (key.GetSize() == 4) {
      std::ranges::stable_sort(
          values_by_key,

          [&](auto &a, auto &b) {
            auto va = util::read_data<uint32_t>(a.first.data());
            auto vb = util::read_data<uint32_t>(b.first.data());
            return va < vb;
          });
    } else {
      LOG(BUG) << "invalid integer argument size. 4 or 8  expected, but "
               << key.GetSize() << " provided";
    }

  } else if (key.IsStringTy()) {
    std::ranges::stable_sort(values_by_key, [&](auto &a, auto &b) {
      return strncmp(reinterpret_cast<const char *>(a.first.data()),
                     reinterpret_cast<const char *>(b.first.data()),
                     key.GetSize()) < 0;
    });
  }
}

const util::FuncsModulesMap &BPFtrace::get_traceable_funcs() const
{
  if (traceable_funcs_.empty())
    traceable_funcs_ = util::parse_traceable_funcs();

  return traceable_funcs_;
}

const util::FuncsModulesMap &BPFtrace::get_raw_tracepoints() const
{
  if (raw_tracepoints_.empty())
    raw_tracepoints_ = util::parse_rawtracepoints();

  return raw_tracepoints_;
}

bool BPFtrace::is_traceable_func(const std::string &func_name) const
{
  const auto &funcs = get_traceable_funcs();
  return funcs.contains(func_name);
}

std::unordered_set<std::string> BPFtrace::get_func_modules(
    const std::string &func_name) const
{
  const auto &funcs = get_traceable_funcs();
  auto mod = funcs.find(func_name);
  return mod != funcs.end() ? mod->second : std::unordered_set<std::string>();
}

std::unordered_set<std::string> BPFtrace::get_raw_tracepoint_modules(
    const std::string &name) const
{
  const auto &rts = get_raw_tracepoints();
  auto mod = rts.find(name);
  return mod != rts.end() ? mod->second : std::unordered_set<std::string>();
}

const std::optional<struct stat> &BPFtrace::get_pidns_self_stat() const
{
  static std::optional<struct stat> pidns = []() -> std::optional<struct stat> {
    struct stat s;
    if (::stat("/proc/self/ns/pid", &s)) {
      if (errno == ENOENT)
        return std::nullopt;
      throw std::runtime_error(
          std::string("Failed to stat /proc/self/ns/pid: ") +
          std::strerror(errno));
    }
    return s;
  }();

  return pidns;
}

Dwarf *BPFtrace::get_dwarf(const std::string &filename)
{
  auto dwarf = dwarves_.find(filename);
  if (dwarf == dwarves_.end()) {
    dwarf =
        dwarves_.emplace(filename, Dwarf::GetFromBinary(this, filename)).first;
  }
  return dwarf->second.get();
}

Dwarf *BPFtrace::get_dwarf(const ast::AttachPoint &attachpoint)
{
  auto probe_type = probetype(attachpoint.provider);
  if (probe_type != ProbeType::uprobe && probe_type != ProbeType::uretprobe)
    return nullptr;

  return get_dwarf(attachpoint.target);
}

int BPFtrace::create_pcaps()
{
  for (auto arg : resources.skboutput_args_) {
    auto file = std::get<0>(arg);

    if (pcap_writers_.contains(file)) {
      return 0;
    }

    auto writer = std::make_unique<PCAPwriter>();

    if (!writer->open(file))
      return -1;

    pcap_writers_[file] = std::move(writer);
  }

  return 0;
}

void BPFtrace::close_pcaps()
{
  for (auto &writer : pcap_writers_) {
    writer.second->close();
  }
}

bool BPFtrace::write_pcaps(uint64_t id,
                           uint64_t ns,
                           uint8_t *pkt,
                           unsigned int size)
{
  if (boottime_) {
    ns = (boottime_->tv_sec * 1e9) + (boottime_->tv_nsec + ns);
  }

  auto file = std::get<0>(resources.skboutput_args_.at(id));
  auto &writer = pcap_writers_.at(file);

  return writer->write(ns, pkt, size);
}

void BPFtrace::parse_module_btf(const std::set<std::string> &modules)
{
  btf_->load_module_btfs(modules);
}

bool BPFtrace::has_btf_data() const
{
  return btf_->has_data();
}

// Retrieves the list of kernel modules for all attachpoints. Will be used to
// identify modules whose BTF we need to parse.
// Currently, this is useful for fentry/fexit, k(ret)probes, tracepoints,
// and raw tracepoints
std::set<std::string> BPFtrace::list_modules(const ast::ASTContext &ctx)
{
  std::set<std::string> modules;
  for (const auto &probe : ctx.root->probes) {
    for (const auto &ap : probe->attach_points) {
      auto probe_type = probetype(ap->provider);
      if (probe_type == ProbeType::fentry || probe_type == ProbeType::fexit ||
          probe_type == ProbeType::rawtracepoint ||
          ((probe_type == ProbeType::kprobe ||
            probe_type == ProbeType::kretprobe) &&
           !ap->target.empty())) {
        if (ap->expansion != ast::ExpansionType::NONE) {
          for (const auto &match : probe_matcher_->get_matches_for_ap(*ap)) {
            std::string func = match;
            util::erase_prefix(func);
            auto match_modules = probe_type == ProbeType::rawtracepoint
                                     ? get_raw_tracepoint_modules(func)
                                     : get_func_modules(func);
            modules.insert(match_modules.begin(), match_modules.end());
          }
        } else
          modules.insert(ap->target);
      } else if (probe_type == ProbeType::tracepoint) {
        // For now, we support this for a single target only since tracepoints
        // need dumping of C definitions BTF and that is not available for
        // multiple modules at once.
        modules.insert(ap->target);
      }
    }
  }
  return modules;
}

} // namespace bpftrace
