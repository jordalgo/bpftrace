#pragma once

#include <string>
#include <vector>

#include <cereal/access.hpp>

#include "types.h"

namespace bpftrace {

class BPFtrace;

class MapKey {
public:
  MapKey() = default;
  explicit MapKey(SizedType &&arg) : arg_(std::move(arg))
  {
  }

  SizedType arg_;

  bool operator!=(const MapKey &k) const;

  size_t size() const;
  std::string argument_type() const;
  std::string argument_value_str(BPFtrace &bpftrace,
                                 const std::vector<uint8_t> &data) const;
  static std::string argument_value(BPFtrace &bpftrace,
                                    const SizedType &arg,
                                    const void *data,
                                    bool is_top_level = false);

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(arg_);
  }
};

} // namespace bpftrace
