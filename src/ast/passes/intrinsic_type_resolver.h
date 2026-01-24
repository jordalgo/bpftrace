#pragma once

#include "ast/pass_manager.h"
#include "ast/visitor.h"

namespace bpftrace {
class BPFtrace;
} // namespace bpftrace

namespace bpftrace::ast {

class CDefinitions;

class IntrinsicTypeResolver : public Visitor<IntrinsicTypeResolver> {
public:
  explicit IntrinsicTypeResolver(BPFtrace &bpftrace,
                                 CDefinitions &c_definitions);

  using Visitor<IntrinsicTypeResolver>::visit;
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Identifier &identifier);
  void visit(Probe &probe);

private:
  Probe *get_probe(Node &node, std::string name = "");
  AddrSpace find_addrspace(ProbeType pt);
  void check_stack_call(Call &call, bool kernel);

  BPFtrace &bpftrace_;
  CDefinitions &c_definitions_;
  Node *top_level_node_ = nullptr;
  std::string func_;
};

} // namespace bpftrace::ast
