#pragma once

#include <unistd.h>

namespace bpftrace::util {

// A wrapper around a file descriptor that closes it on destruction.
class FD {
public:
  explicit FD(int fd) : fd_(fd)
  {
  }

  ~FD()
  {
    close();
  }

  FD(const FD&) = delete;
  FD& operator=(const FD&) = delete;
  FD(FD&& other) noexcept : fd_(other.fd_)
  {
    other.fd_ = -1;
  }
  FD& operator=(FD&& other) noexcept
  {
    if (this != &other) {
      close();
      fd_ = other.fd_;
      other.fd_ = -1;
    }
    return *this;
  }

  int get() const noexcept
  {
    return fd_;
  }

  operator int() const noexcept
  {
    return fd_;
  }

private:
  void close()
  {
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

  int fd_;
};

} // namespace bpftrace::util
