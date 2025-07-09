#include <string>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include "log.h"
#include <bpf/bpf.h>
#include <linux/btf.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#include <bpf/btf.h>
#pragma GCC diagnostic pop
#include "scopeguard.h"

namespace bpftrace::util {

std::string get_prog_full_name(const struct bpf_prog_info *prog_info,
                               int prog_fd)
{
  const char *prog_name = prog_info->name;
  const struct btf_type *func_type;
  struct bpf_func_info finfo = {};
  struct bpf_prog_info info = {};
  __u32 info_len = sizeof(info);
  struct btf *prog_btf = nullptr;

  std::string name = std::string(prog_name);

  if (!prog_info->btf_id || prog_info->nr_func_info == 0) {
    return name;
  }

  info.nr_func_info = 1;
  info.func_info_rec_size = prog_info->func_info_rec_size;
  info.func_info_rec_size = std::min<unsigned long>(info.func_info_rec_size,
                                                    sizeof(finfo));
  info.func_info = reinterpret_cast<__u64>(&finfo);

  if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len)) {
    return name;
  }

  prog_btf = btf__load_from_kernel_by_id(info.btf_id);
  if (!prog_btf) {
    return name;
  }

  func_type = btf__type_by_id(prog_btf, finfo.type_id);
  if (!func_type || !btf_is_func(func_type)) {
    btf__free(prog_btf);
    return name;
  }

  prog_name = btf__name_by_offset(prog_btf, func_type->name_off);
  name = std::string(prog_name);
  btf__free(prog_btf);
  return name;
}

int get_fd_for_bpf_prog(const std::string &bpf_prog_name)
{
  __u32 id = 0;
  while (bpf_prog_get_next_id(id, &id) == 0) {
    int fd = bpf_prog_get_fd_by_id(id);
    // Don't close the fd if we return it;
    // it needs to stay alive until after program attaching/loading
    bool close_fd = true;

    SCOPE_EXIT
    {
      if (close_fd && fd >= 0) {
        close(fd);
      }
    };

    if (fd < 0) {
      LOG(V1) << "Error getting FD for BPF program ID " << id;
      continue;
    }

    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);

    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
      LOG(V1) << "Error getting info for BPF program FD";
      continue;
    }

    if (get_prog_full_name(&info, fd) == bpf_prog_name) {
      close_fd = false;
      return fd;
    }

    // Now let's look at the subprograms for this program
    // if they exist
    if (info.nr_func_info == 0) {
      continue;
    }

    struct btf *btf = nullptr;
    size_t nr_func_info = info.nr_func_info;
    size_t rec_size = info.func_info_rec_size;
    std::vector<char> fi_mem(nr_func_info * rec_size);

    btf = btf__load_from_kernel_by_id(info.btf_id);
    if (!btf) {
      LOG(V1) << "Failed to load BTF for BPF program ID " << info.btf_id;
      continue;
    }

    SCOPE_EXIT
    {
      btf__free(btf);
    };

    info = {};
    info.nr_func_info = nr_func_info;
    info.func_info_rec_size = rec_size;
    info.func_info = reinterpret_cast<__u64>(fi_mem.data());

    if (bpf_prog_get_info_by_fd(fd, &info, &info_len) != 0) {
      continue;
    }

    auto *func_info = reinterpret_cast<struct bpf_func_info *>(info.func_info);
    if (!func_info) {
      continue;
    }

    const struct btf_type *t = nullptr;
    for (__u32 i = 0; i < nr_func_info; i++) {
      t = btf__type_by_id(btf, (func_info + i)->type_id);
      if (!t) {
        continue;
      }

      const char *func_name = btf__name_by_offset(btf, t->name_off);
      if (std::string(func_name) == bpf_prog_name) {
        close_fd = false;
        return fd;
      }
    }
  }

  return -1;
}

std::unordered_set<std::string> get_bpf_program_symbols()
{
  std::unordered_set<std::string> symbols;
  __u32 id = 0;
  while (bpf_prog_get_next_id(id, &id) == 0) {
    int fd = bpf_prog_get_fd_by_id(id);

    if (fd < 0) {
      continue;
    }

    SCOPE_EXIT
    {
      close(fd);
    };

    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);

    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
      continue;
    }

    symbols.insert(get_prog_full_name(&info, fd));

    // Now let's look at the subprograms for this program
    // if they exist
    if (info.nr_func_info == 0) {
      continue;
    }

    struct btf *btf = nullptr;
    size_t nr_func_info = info.nr_func_info;
    size_t rec_size = info.func_info_rec_size;
    std::vector<char> fi_mem(nr_func_info * rec_size);

    btf = btf__load_from_kernel_by_id(info.btf_id);
    if (!btf) {
      continue;
    }

    SCOPE_EXIT
    {
      btf__free(btf);
    };

    info = {};
    info.nr_func_info = nr_func_info;
    info.func_info_rec_size = rec_size;
    info.func_info = reinterpret_cast<__u64>(fi_mem.data());

    if (bpf_prog_get_info_by_fd(fd, &info, &info_len) != 0) {
      continue;
    }

    auto *func_info = reinterpret_cast<struct bpf_func_info *>(info.func_info);
    if (!func_info) {
      continue;
    }

    const struct btf_type *t = nullptr;
    for (__u32 i = 0; i < nr_func_info; i++) {
      t = btf__type_by_id(btf, (func_info + i)->type_id);
      if (!t) {
        continue;
      }

      const char *func_name = btf__name_by_offset(btf, t->name_off);
      symbols.insert(std::string(func_name));
    }
  }

  return symbols;
}

} // namespace bpftrace::util
