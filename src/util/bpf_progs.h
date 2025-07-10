#pragma once

#include "util/fd.h"
#include <string>
#include <unordered_set>

namespace bpftrace::util {

// These include all BPF programs and subprograms
FD get_fd_for_bpf_prog(const std::string& bpf_prog_name);
std::unordered_set<std::string> get_bpf_program_symbols();

} // namespace bpftrace::util
