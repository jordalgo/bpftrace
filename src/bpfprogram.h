#pragma once

#include <bpf/libbpf.h>

#include "bpffeature.h"
#include "btf.h"
#include "config.h"
#include "probe_types.h"
#include "util/fd.h"

#include "util/result.h"

namespace bpftrace {

class AttachTargetError : public ErrorInfo<AttachTargetError> {
public:
  AttachTargetError(std::string &&msg) : msg(std::move(msg)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string msg;
};

class BpfBytecode;
class BPFtrace;

// This class abstracts a single BPF program by encapsulating libbpf's
// 'struct bpf_prog'.
class BpfProgram {
public:
  explicit BpfProgram(struct bpf_program *bpf_prog);

  void set_prog_type(const Probe &probe);
  void set_expected_attach_type(const Probe &probe, BPFfeature &feature);
  Result<OK> set_attach_target(const Probe &probe, const BTF &btf);
  void set_no_autoattach();

  int fd() const;
  struct bpf_program *bpf_prog() const;

  BpfProgram(const BpfProgram &) = delete;
  BpfProgram &operator=(const BpfProgram &) = delete;
  BpfProgram(BpfProgram &&) = default;
  BpfProgram &operator=(BpfProgram &&) = default;

private:
  struct bpf_program *bpf_prog_;
  // This fd is specifically for attaching to other running BPF programs.
  util::FD attach_fd_ = util::FD(-1);
};

} // namespace bpftrace
