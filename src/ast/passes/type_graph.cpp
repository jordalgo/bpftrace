#include "ast/passes/type_graph.h"
#include "ast/ast.h"
#include "ast/passes/cast_creator.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/intrinsic_type_resolver.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"

#include <algorithm>
#include <functional>

namespace bpftrace::ast {

namespace {

template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};

using ScopedVariable = std::pair<Node *, std::string>;
using GraphNode = std::variant<Node *, Typeof *, ScopedVariable, std::string>;
using ResolvedNode = std::pair<GraphNode, SizedType>;

struct MapType {
  SizedType key_type;
  SizedType value_type;
};

struct ResolvedSource {
  GraphNode source;
  SizedType type;
  Node *error_node = nullptr;
  std::optional<GraphNode> ptr_source;
};

using GraphNodeCallback = std::function<std::optional<
    SizedType>(const GraphNode &, const std::vector<ResolvedSource> &)>;

struct TypeSources {
  std::vector<ResolvedSource> sources;
  uint64_t num_resolved = 0;
  GraphNodeCallback callback = [](const GraphNode &,
                                  const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    if (sources.size() == 1) {
      return sources.back().type;
    }
    LOG(BUG) << "Default callback expects exactly one source";
    return std::nullopt;
  };
};

struct ScopedVariableHash {
  std::size_t operator()(const ScopedVariable &sv) const
  {
    auto h1 = std::hash<Node *>{}(sv.first);
    auto h2 = std::hash<std::string>{}(sv.second);
    return h1 ^ (h2 << 1);
  }
};

struct GraphNodeHash {
  std::size_t operator()(const GraphNode &gn) const
  {
    return std::visit(
        [](const auto &val) -> std::size_t {
          using T = std::decay_t<decltype(val)>;
          if constexpr (std::is_same_v<T, Node *>) {
            return std::hash<Node *>{}(val);
          } else if constexpr (std::is_same_v<T, Typeof *>) {
            return std::hash<Typeof *>{}(val);
          } else if constexpr (std::is_same_v<T, std::string>) {
            return std::hash<std::string>{}(val);
          } else {
            return ScopedVariableHash{}(val);
          }
        },
        gn);
  }
};

using LockedNodes = std::unordered_map<GraphNode, SizedType, GraphNodeHash>;

class TypeGraphPass : public Visitor<TypeGraphPass> {
public:
  explicit TypeGraphPass(ASTContext &ast,
                         BPFtrace &bpftrace,
                         CDefinitions &c_definitions,
                         LockedNodes locked_nodes = {})
      : ast_(ast),
        bpftrace_(bpftrace),
        c_definitions_(c_definitions),
        locked_nodes_(std::move(locked_nodes))
  {
  }

  using Visitor<TypeGraphPass>::visit;
  void visit(ArrayAccess &arr);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(Binop &binop);
  void visit(BlockExpr &block);
  void visit(Boolean &boolean);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Cast &cast);
  void visit(Comptime &comptime);
  void visit(ExprStatement &expr);
  void visit(Identifier &identifier);
  void visit(IfExpr &if_expr);
  void visit(Integer &integer);
  void visit(Map &map);
  void visit(MapAccess &acc);
  void visit(MapAddr &map_addr);
  void visit(NegativeInteger &integer);
  void visit(Offsetof &offof);
  void visit(Probe &probe);
  void visit(Record &record);
  void visit(Sizeof &szof);
  void visit(String &string);
  void visit(Tuple &tuple);
  void visit(TupleAccess &acc);
  void visit(Typeof &typeof);
  void visit(Typeinfo &typeinfo);
  void visit(Unop &unop);
  void visit(VarDeclStatement &decl);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);

  bool resolve();
  LockedNodes get_locked_nodes();

  const std::vector<Comptime *> &get_unresolved_comptimes() const
  {
    return unresolved_comptimes_;
  }

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  CDefinitions &c_definitions_;
  const LockedNodes locked_nodes_;
  std::vector<ResolvedNode> resolved_nodes_;
  std::unordered_map<GraphNode, std::vector<GraphNode>, GraphNodeHash>
      source_to_consumers_;
  std::unordered_map<GraphNode, TypeSources, GraphNodeHash>
      consumer_to_sources_;
  std::unordered_map<Node *, std::unordered_map<std::string, SizedType>>
      variables_;
  // These are variables that have a declaration with a type, e.g. let $a:
  // uint16;
  std::unordered_set<ScopedVariable, ScopedVariableHash> decl_variables_;
  std::unordered_map<std::string, MapType> maps_;
  // At the moment we iterate over the stack from top to
  // bottom as variable shadowing is not supported.
  std::vector<Node *> scope_stack_;
  int introspection_level_ = 0;
  std::unordered_set<GraphNode, GraphNodeHash> introspected_nodes_;

  std::vector<Comptime *> unresolved_comptimes_;
  // Tracks the "source" of pointer types (the variable/map being addressed).
  // Key: the ScopedVariable or map value/key holding the pointer Value (the
  // variable/map being addressed - the source).
  std::unordered_map<GraphNode, GraphNode, GraphNodeHash> pointer_sources_;

  void resolve_struct_type(SizedType &type, Node &node);
  bool check_offsetof_type(Offsetof &offof, SizedType cstruct);
  std::optional<SizedType> update_variable_type(
      const ScopedVariable &scoped_var,
      const SizedType &type,
      Node &error_node,
      std::optional<GraphNode> ptr_source = std::nullopt);
  std::optional<SizedType> update_map_value(
      const std::string map_name,
      const SizedType &type,
      Node &error_node,
      std::optional<GraphNode> ptr_source = std::nullopt);
  void propagate_resolved_type(const GraphNode &source, const SizedType &type);
  Node *find_variable_scope(const std::string &var_ident, bool safe = false);
  std::string get_map_value_name(const std::string &ident);
  std::string get_map_key_name(const std::string &ident);
  void add_to_graph(const GraphNode &consumer,
                  const GraphNode &source,
                  Node *error_node = nullptr,
                  std::optional<GraphNode> ptr_source = std::nullopt);
  bool check_locked_node(const GraphNode &node,
                         const SizedType &type,
                         Node &error_node,
                         const std::string &name);
  GraphNode get_pointer_source(Expression &expr);
  bool is_same_pointer_source(const GraphNode &node_key,
                              const GraphNode &ptr_source,
                              const SizedType &incoming_type,
                              const SizedType &current_type);
};

class IntrospectionFolder
    : public Visitor<IntrospectionFolder, std::optional<Expression>> {
public:
  IntrospectionFolder(ASTContext &ast) : ast_(ast) {};

  using Visitor<IntrospectionFolder, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Expression &expr);
  std::optional<Expression> visit(Offsetof &offof);
  std::optional<Expression> visit(Sizeof &szof);
  std::optional<Expression> visit(Typeinfo &typeinfo);

private:
  ASTContext &ast_;
};

std::optional<SizedType> get_promoted_int(const SizedType &currentType,
                                          const SizedType &newType)
{
  bool currentSigned = currentType.IsSigned();
  bool newSigned = newType.IsSigned();
  auto currentSize = currentType.GetSize();
  auto newSize = newType.GetSize();

  if (currentSigned != newSigned) {
    if (currentSigned) {
      if (currentSize > newSize) {
        return currentType;
      }
    } else if (newSigned) {
      if (newSize > currentSize) {
        return newType;
      }
    }

    size_t promoted_size = std::max(currentSize, newSize) * 2;
    if (promoted_size > 8) {
      return std::nullopt;
    } else {
      return CreateInteger(promoted_size * 8, true);
    }
  }

  // Same sign - return the larger of the two
  size_t promoted_size = std::max(currentSize, newSize);
  return CreateInteger(promoted_size * 8, currentSigned);
}

// Forward declarations for mutual recursion
std::optional<SizedType> get_promoted_tuple(const SizedType &currentType,
                                            const SizedType &newType);
std::optional<SizedType> get_promoted_record(const SizedType &currentType,
                                             const SizedType &newType);

std::optional<SizedType> get_promoted_tuple(const SizedType &currentType,
                                            const SizedType &newType)
{
  assert(currentType.IsTupleTy() && currentType.IsCompatible(newType));

  std::vector<SizedType> new_elems;
  for (ssize_t i = 0; i < newType.GetFieldCount(); i++) {
    auto currentElemTy = currentType.GetField(i).type;
    auto newElemTy = newType.GetField(i).type;
    if (currentElemTy.IsIntegerTy()) {
      auto updatedTy = get_promoted_int(currentElemTy, newElemTy);
      if (!updatedTy) {
        return std::nullopt;
      }
      new_elems.emplace_back(*updatedTy);
    } else if (currentElemTy.IsTupleTy()) {
      auto new_elem = get_promoted_tuple(currentElemTy, newElemTy);
      if (!new_elem) {
        return std::nullopt;
      }
      new_elems.emplace_back(*new_elem);
    } else if (currentElemTy.IsRecordTy()) {
      auto new_elem = get_promoted_record(currentElemTy, newElemTy);
      if (!new_elem) {
        return std::nullopt;
      }
      new_elems.emplace_back(*new_elem);
    } else if (currentElemTy.IsStringTy()) {
      currentElemTy.SetSize(
          std::max(currentElemTy.GetSize(), newElemTy.GetSize()));
      new_elems.emplace_back(currentElemTy);
    } else if (currentElemTy.IsArrayTy()) {
      if ((currentElemTy.GetSize() != newElemTy.GetSize()) ||
          (currentElemTy.GetElementTy() != newElemTy.GetElementTy())) {
        return std::nullopt;
      }
      new_elems.emplace_back(currentElemTy);
    } else {
      new_elems.emplace_back(currentElemTy);
    }
  }
  return CreateTuple(Struct::CreateTuple(new_elems));
}

std::optional<SizedType> get_promoted_record(const SizedType &currentType,
                                             const SizedType &newType)
{
  assert(currentType.IsRecordTy() && currentType.IsCompatible(newType));

  std::vector<SizedType> new_elems;
  std::vector<std::string_view> names;
  // Maintain the ordering of the currentType
  for (const auto &currentElemField : currentType.GetFields()) {
    names.emplace_back(currentElemField.name);

    auto currentElemTy = currentElemField.type;
    auto newElemTy = newType.GetField(currentElemField.name).type;
    if (currentElemTy.IsIntegerTy()) {
      auto updatedTy = get_promoted_int(currentElemTy, newElemTy);
      if (!updatedTy) {
        return std::nullopt;
      }
      new_elems.emplace_back(*updatedTy);
    } else if (currentElemTy.IsTupleTy()) {
      auto new_elem = get_promoted_tuple(currentElemTy, newElemTy);
      if (!new_elem) {
        return std::nullopt;
      }
      new_elems.emplace_back(*new_elem);
    } else if (currentElemTy.IsRecordTy()) {
      auto new_elem = get_promoted_record(currentElemTy, newElemTy);
      if (!new_elem) {
        return std::nullopt;
      }
      new_elems.emplace_back(*new_elem);
    } else if (currentElemTy.IsStringTy()) {
      currentElemTy.SetSize(
          std::max(currentElemTy.GetSize(), newElemTy.GetSize()));
      new_elems.emplace_back(currentElemTy);
    } else if (currentElemTy.IsArrayTy()) {
      if ((currentElemTy.GetSize() != newElemTy.GetSize()) ||
          (currentElemTy.GetElementTy() != newElemTy.GetElementTy())) {
        return std::nullopt;
      }
      new_elems.emplace_back(currentElemTy);
    } else {
      new_elems.emplace_back(currentElemTy);
    }
  }
  return CreateRecord(Struct::CreateRecord(new_elems, names));
}

std::optional<SizedType> promote_type(const SizedType &currentType,
                                      const SizedType &newType)
{
  if (currentType.IsNoneTy() || currentType == newType) {
    return newType;
  }

  if (!currentType.IsCompatible(newType)) {
    return std::nullopt;
  }

  auto promotedType = currentType;
  if (newType.IsIntegerTy()) {
    auto int_promoted = get_promoted_int(newType, currentType);
    if (!int_promoted) {
      LOG(BUG) << "Couldn't promote type, this should have "
                  "been caught by IsCompatible";
    }
    promotedType = *int_promoted;
  } else if (promotedType.IsStringTy()) {
    if (newType.GetSize() > currentType.GetSize()) {
      promotedType = newType;
    }
  } else if (promotedType.IsTupleTy()) {
    auto tuple_promoted = get_promoted_tuple(currentType, newType);
    if (!tuple_promoted) {
      return std::nullopt;
    }
    promotedType = *tuple_promoted;
  } else if (promotedType.IsRecordTy()) {
    auto record_promoted = get_promoted_record(currentType, newType);
    if (!record_promoted) {
      return std::nullopt;
    }
    promotedType = *record_promoted;
  }

  return promotedType;
}

bool TypeGraphPass::check_offsetof_type(Offsetof &offof, SizedType cstruct)
{
  // Check if all sub-fields are present.
  for (const auto &field : offof.field) {
    if (!cstruct.IsCStructTy()) {
      offof.addError() << "'" << cstruct << "' " << "is not a c_struct type.";
      return false;
    } else if (!bpftrace_.structs.Has(cstruct.GetName())) {
      offof.addError() << "'" << cstruct.GetName() << "' does not exist.";
      return false;
    } else if (!cstruct.HasField(field)) {
      offof.addError() << "'" << cstruct.GetName() << "' "
                       << "has no field named " << "'" << field << "'";
      return false;
    } else {
      // Get next sub-field
      const auto &f = cstruct.GetField(field);
      cstruct = f.type;
    }
  }
  return true;
}

} // namespace

void TypeGraphPass::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  visit(arr.indexpr);

  add_to_graph(&arr, &arr.expr.node());
  consumer_to_sources_[&arr].callback =
      [&arr](const GraphNode &, const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    auto &type = sources.back().type;
    if (type.IsArrayTy()) {
      arr.element_type = type.GetElementTy();
    } else if (type.IsPtrTy()) {
      arr.element_type = type.GetPointeeTy();
    } else if (type.IsStringTy()) {
      arr.element_type = CreateInt8();
    } else {
      arr.addError() << "The array index operator [] can only be "
                        "used on arrays and pointers, found "
                     << type << ".";
    }

    arr.element_type.SetAS(type.GetAS());

    // BPF verifier cannot track BTF information for double pointers so we
    // cannot propagate is_internal for arrays of pointers and we need to
    // reset it on the array type as well. Indexing a pointer as an array
    // also can't be verified, so the same applies there.
    if (arr.element_type.IsPtrTy() || type.IsPtrTy()) {
      arr.element_type.is_internal = false;
    } else {
      arr.element_type.is_internal = type.is_internal;
    }

    return arr.element_type;
  };
}

void TypeGraphPass::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);

  auto map_name = assignment.map_access->map->ident;
  auto value_name = get_map_value_name(map_name);
  auto ptr_source = get_pointer_source(assignment.expr);

  add_to_graph(value_name, &assignment.expr.node(), &assignment, ptr_source);
  consumer_to_sources_[value_name].callback =
      [this, map_name](const GraphNode &,
                       const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    for (const auto &src : sources) {
      auto result = update_map_value(
          map_name, src.type, *src.error_node, src.ptr_source);
      if (!result) {
        return std::nullopt;
      }
    }
    return maps_[map_name].value_type;
  };
}

void TypeGraphPass::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);
  visit(assignment.var_decl);

  if (std::holds_alternative<VarDeclStatement *>(assignment.var_decl)) {
    auto *var_decl = std::get<VarDeclStatement *>(assignment.var_decl);
    if (var_decl->typeof) {
      // The type of this variable is determined by the typeof, not the r-value.
      return;
    }
  }

  Node *var_scope = find_variable_scope(assignment.var()->ident, true);
  ScopedVariable scoped_var = std::make_pair(var_scope,
                                             assignment.var()->ident);
  auto ptr_source = get_pointer_source(assignment.expr);

  add_to_graph(scoped_var, &assignment.expr.node(), &assignment, ptr_source);
  consumer_to_sources_[scoped_var].callback =
      [this, scoped_var](const GraphNode &,
                         const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    for (const auto &src : sources) {
      auto result = update_variable_type(
          scoped_var, src.type, *src.error_node, src.ptr_source);
      if (!result) {
        return std::nullopt;
      }
    }
    return variables_[scoped_var.first][scoped_var.second];
  };
}

void TypeGraphPass::visit(Builtin &builtin)
{
  resolved_nodes_.emplace_back(&builtin, builtin.builtin_type);
}

void TypeGraphPass::visit(Call &call)
{
  // Visit children to wire up graph edges for arguments
  for (auto &varg : call.vargs) {
    visit(varg);
  }
  resolved_nodes_.emplace_back(&call, call.return_type);
}

void TypeGraphPass::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  if (is_comparison_op(op.op)) {
    op.result_type = CreateBool();
    resolved_nodes_.emplace_back(&op, op.result_type);
    return;
  }

  add_to_graph(&op, &op.left.node());
  add_to_graph(&op, &op.right.node());
  consumer_to_sources_[&op].callback =
      [&op](const GraphNode &, const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    SizedType result = CreateNone();
    for (const auto &src : sources) {
      auto promoted = promote_type(result, src.type);
      if (!promoted) {
        op.addError() << "Binop: Type " << src.type
                      << " is not compatible with the other type " << result;
        return std::nullopt;
      }
      result = *promoted;
    }
    op.result_type = result;
    return result;
  };
}

void TypeGraphPass::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  visit(block.stmts);
  visit(block.expr);

  add_to_graph(&block, &block.expr.node());
  scope_stack_.pop_back();
}

void TypeGraphPass::visit(Boolean &boolean)
{
  resolved_nodes_.emplace_back(&boolean, boolean.type());
}

void TypeGraphPass::visit(Cast &cast)
{
  visit(cast.expr);
  visit(cast.typeof);

  add_to_graph(&cast, cast.typeof);
}

void TypeGraphPass::visit(Comptime &comptime)
{
  visit(comptime.expr);
  unresolved_comptimes_.emplace_back(&comptime);
}

void TypeGraphPass::visit(ExprStatement &expr)
{
  visit(expr.expr);
}

void TypeGraphPass::visit(Identifier &identifier)
{
  if (identifier.type().IsNoneTy() && introspection_level_ > 0) {
    identifier.ident_type = bpftrace_.btf_->get_stype(identifier.ident);
  }

  resolved_nodes_.emplace_back(&identifier, identifier.type());
}

void TypeGraphPass::visit(IfExpr &if_expr)
{
  if (auto *comptime = if_expr.cond.as<Comptime>()) {
    visit(comptime->expr);
    unresolved_comptimes_.emplace_back(comptime);
    return; // Skip visiting this `if` for now.
  }

  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);
}

void TypeGraphPass::visit(Integer &integer)
{
  resolved_nodes_.emplace_back(&integer, integer.type());
}

void TypeGraphPass::visit(Map &map)
{
  maps_.insert({ map.ident, MapType{ CreateNone(), CreateNone() } });

  auto key_name = get_map_key_name(map.ident);
  auto value_name = get_map_value_name(map.ident);

  add_to_graph(&map, key_name);
  add_to_graph(&map, value_name);
  consumer_to_sources_[&map].callback =
      [&map](const GraphNode &, const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    for (const auto &src : sources) {
      if (auto *str = std::get_if<std::string>(&src.source)) {
        if (str->ends_with("__key")) {
          map.key_type = src.type;
        } else {
          map.value_type = src.type;
          // End the chain here as the only expressions depending on a map
          // expression are waiting for it's key type - for the value type,
          // expressions wait on a map access.
        }
      }
    }
    return map.key_type;
  };

  if (introspection_level_ > 0) {
    introspected_nodes_.insert(map.ident);
  }
}

void TypeGraphPass::visit(MapAccess &acc)
{
  visit(acc.map);
  visit(acc.key);

  auto key_name = get_map_key_name(acc.map->ident);
  auto ptr_source = get_pointer_source(acc.key);

  add_to_graph(key_name, &acc.key.node(), &acc, ptr_source);
  consumer_to_sources_[key_name].callback =
      [this, &acc, key_name](const GraphNode &,
                             const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    for (const auto &src : sources) {
      if (!maps_.contains(acc.map->ident)) {
        LOG(BUG) << "Map should have been added to map";
      }

      if (!check_locked_node(
              key_name, src.type, *src.error_node, acc.map->ident)) {
        return std::nullopt;
      }

      auto &map = maps_[acc.map->ident];

      auto promoted = promote_type(map.key_type, src.type);
      if (promoted) {
        if (promoted->IsPtrTy() && src.ptr_source.has_value()) {
          pointer_sources_[key_name] = *src.ptr_source;
        }

        map.key_type = *promoted;
      } else {
        // The types are incompatible, check if it's ok for same-source
        // pointers
        if (src.ptr_source.has_value() &&
            is_same_pointer_source(
                key_name, *src.ptr_source, src.type, map.key_type)) {
          map.key_type = src.type;
        } else {
          src.error_node->addError()
              << "Type mismatch for " << acc.map->ident << ": "
              << "trying to assign key of type '" << src.type
              << "' when map already has key type '" << map.key_type << "'";
          return std::nullopt;
        }
      }
    }
    return maps_[acc.map->ident].key_type;
  };

  add_to_graph(&acc, get_map_value_name(acc.map->ident));
}

void TypeGraphPass::visit(MapAddr &map_addr)
{
  visit(map_addr.map);

  // This needs to be fixed as neither the map value or map key are the actual
  // map's type
  add_to_graph(&map_addr, get_map_value_name(map_addr.map->ident));
  consumer_to_sources_[&map_addr].callback =
      [&map_addr](const GraphNode &, const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    auto &type = sources.back().type;
    map_addr.map_addr_type = CreatePointer(type, type.GetAS());
    return map_addr.map_addr_type;
  };
}

void TypeGraphPass::visit(NegativeInteger &integer)
{
  resolved_nodes_.emplace_back(&integer, integer.type());
}

void TypeGraphPass::visit(Offsetof &offof)
{
  if (std::holds_alternative<SizedType>(offof.record)) {
    auto &ty = std::get<SizedType>(offof.record);
    resolve_struct_type(ty, offof);
    check_offsetof_type(offof, ty);
    resolved_nodes_.emplace_back(&offof, offof.type());
  } else {
    auto &expr = std::get<Expression>(offof.record);
    visit(expr);
    add_to_graph(&offof, &expr.node());
    consumer_to_sources_[&offof].callback =
        [this, &offof](const GraphNode &,
                       const std::vector<ResolvedSource> &sources)
        -> std::optional<SizedType> {
      auto type = sources.back().type;
      resolve_struct_type(type, offof);
      if (!check_offsetof_type(offof, type)) {
        return std::nullopt;
      }
      return offof.type();
    };
  }
}

void TypeGraphPass::visit(Probe &probe)
{
  visit(probe.attach_points);
  visit(probe.block);
}

void TypeGraphPass::visit(Record &record)
{
  for (auto *named_arg : record.elems) {
    auto &elem = named_arg->expr;
    visit(elem);

    add_to_graph(&record, &elem.node());
  }
  consumer_to_sources_[&record].callback =
      [&record](const GraphNode &, const std::vector<ResolvedSource> &)
      -> std::optional<SizedType> {
    std::vector<SizedType> elements;
    std::vector<std::string_view> names;
    for (auto *named_arg : record.elems) {
      auto &elem = named_arg->expr;
      if (elem.type().IsNoneTy()) {
        return std::nullopt;
      }
      elements.emplace_back(elem.type());
      names.emplace_back(named_arg->name);
    }
    auto record_type = CreateRecord(Struct::CreateRecord(elements, names));
    record.record_type = record_type;
    return record_type;
  };
}

void TypeGraphPass::visit(Sizeof &szof)
{
  if (std::holds_alternative<SizedType>(szof.record)) {
    auto &ty = std::get<SizedType>(szof.record);
    resolve_struct_type(ty, szof);
    resolved_nodes_.emplace_back(&szof, ty);
  } else {
    auto &expr = std::get<Expression>(szof.record);
    visit(expr);
    add_to_graph(&szof, &expr.node());
    consumer_to_sources_[&szof].callback =
        [&szof](const GraphNode &, const std::vector<ResolvedSource> &)
        -> std::optional<SizedType> {
      // The type of Sizeof is always the same
      return szof.type();
    };
  }
}

void TypeGraphPass::visit(String &str)
{
  resolved_nodes_.emplace_back(&str, str.type());
}

void TypeGraphPass::visit(Typeof &typeof)
{
  if (std::holds_alternative<SizedType>(typeof.record)) {
    auto &ty = std::get<SizedType>(typeof.record);
    resolve_struct_type(ty, typeof);
    resolved_nodes_.emplace_back(&typeof, ty);
  } else {
    auto &expr = std::get<Expression>(typeof.record);
    visit(expr);

    if (auto *ident = expr.as<Identifier>()) {
      auto stype = bpftrace_.btf_->get_stype(ident->ident);
      resolved_nodes_.emplace_back(&typeof, stype);
    } else {
      add_to_graph(&typeof, &expr.node());
    }
  }
}

void TypeGraphPass::visit(Tuple &tuple)
{
  for (auto &elem : tuple.elems) {
    visit(elem);

    add_to_graph(&tuple, &elem.node());
  }
  consumer_to_sources_[&tuple].callback =
      [&tuple](const GraphNode &, const std::vector<ResolvedSource> &)
      -> std::optional<SizedType> {
    std::vector<SizedType> elements;
    for (auto &elem : tuple.elems) {
      if (elem.type().IsNoneTy()) {
        return std::nullopt;
      }
      elements.emplace_back(elem.type());
    }
    auto tuple_type = CreateTuple(Struct::CreateTuple(elements));
    tuple.tuple_type = tuple_type;
    return tuple_type;
  };
}

void TypeGraphPass::visit(TupleAccess &acc)
{
  visit(acc.expr);

  add_to_graph(&acc, &acc.expr.node());
  consumer_to_sources_[&acc].callback =
      [&acc](const GraphNode &, const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    auto &type = sources.back().type;
    if (!type.IsTupleTy()) {
      return std::nullopt;
    }

    if (acc.index < type.GetFields().size()) {
      acc.element_type = type.GetField(acc.index).type;
      return acc.element_type;
    }
    return std::nullopt;
  };
}

void TypeGraphPass::visit(Typeinfo &typeinfo)
{
  ++introspection_level_;
  visit(typeinfo.typeof);
  --introspection_level_;
  add_to_graph(&typeinfo, typeinfo.typeof);
  consumer_to_sources_[&typeinfo].callback =
      [](const GraphNode &, const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    auto &type = sources.back().type;
    auto base_ty_str = to_string(type.GetTy());
    auto full_ty_str = typestr(type);
    std::vector<SizedType> elements = { CreateUInt64(),
                                        CreateString(base_ty_str.size() + 1),
                                        CreateString(full_ty_str.size() + 1) };
    std::vector<std::string_view> names = { "btf_id",
                                            "base_type",
                                            "full_type" };
    return CreateRecord(Struct::CreateRecord(elements, names));
  };
}

void TypeGraphPass::visit(Unop &unop)
{
  visit(unop.expr);

  bool is_inc_dec_op = false;

  switch (unop.op) {
    case Operator::PRE_INCREMENT:
    case Operator::PRE_DECREMENT:
    case Operator::POST_INCREMENT:
    case Operator::POST_DECREMENT:
      is_inc_dec_op = true;
      break;
    default:;
  }

  // Unops are special in that they can be both assignments and expressions. If
  // we're dealing with a map access or variable then treat these like
  // assignments and resolved_types whereby we resolve the type of unop
  // expression and creates a chain that attemps to assign this integer type to
  // the stored map value or variable. This enables us to get error messages on
  // the correct node if we attempt to increment a string or some other invalid
  // type.
  if (is_inc_dec_op) {
    if (auto *acc = unop.expr.as<MapAccess>()) {
      auto map_name = acc->map->ident;
      auto map_value_name = get_map_value_name(map_name);

      resolved_nodes_.emplace_back(&unop, CreateInt64());
      unop.result_type = CreateInt64();
      add_to_graph(map_value_name, &unop, &unop);
      // Set callback if not already set by AssignMapStatement.
      // AssignMapStatement may overwrite this later.  If this callback fires it
      // means there were no other assignments to this map and we rely on this
      // to set the value type
      if (consumer_to_sources_[map_value_name].sources.size() == 1) {
        consumer_to_sources_[map_value_name].callback =
            [this, map_name](const GraphNode &,
                             const std::vector<ResolvedSource> &sources)
            -> std::optional<SizedType> {
          assert(sources.size() == 1);
          if (!maps_.contains(map_name)) {
            LOG(BUG) << "Map should have been added to map";
          }

          auto value_name = get_map_value_name(map_name);

          auto &type = sources.back().type;

          if (!check_locked_node(
                  value_name, type, *sources.back().error_node, map_name)) {
            return std::nullopt;
          }

          auto &map = maps_[map_name];
          map.value_type = type;

          return map.value_type;
        };
      }

      return;
    } else if (auto *var = unop.expr.as<Variable>()) {
      Node *scope = find_variable_scope(var->ident);
      ScopedVariable scoped_var = std::make_pair(scope, var->ident);

      resolved_nodes_.emplace_back(&unop, CreateInt64());
      unop.result_type = CreateInt64();
      add_to_graph(scoped_var, &unop, &unop);
      // Only set the callback if there isn't one already (AssignVarStatement
      // may have already set it). If there is one, the add_to_graph above just
      // adds another source to the existing consumer.  If this callback fires
      // it means there were no other assignments to this variable and we rely
      // on this (or a type declaration) to set the variable type
      if (consumer_to_sources_[scoped_var].sources.size() == 1) {
        consumer_to_sources_[scoped_var].callback =
            [this, scoped_var](const GraphNode &,
                               const std::vector<ResolvedSource> &sources)
            -> std::optional<SizedType> {
          assert(sources.size() == 1);
          Node *scope = scoped_var.first;
          const auto &var = scoped_var.second;
          auto foundVar = variables_[scope].find(var);

          if (foundVar == variables_[scope].end()) {
            LOG(BUG) << "Variable " << var
                     << " should exist in the variables_ map";
          }

          // Only update the variable if it doesn't have a type
          if (foundVar->second.IsNoneTy()) {
            foundVar->second = sources.back().type;
          }

          return foundVar->second;
        };
      }

      return;
    }

    unop.addError() << "The " << opstr(unop)
                    << " operator must be applied to a map or variable";
    return;
  }

  auto valid_ptr_op = is_inc_dec_op || unop.op == Operator::MUL;

  add_to_graph(&unop, &unop.expr.node());
  consumer_to_sources_[&unop].callback =
      [&unop, valid_ptr_op](const GraphNode &,
                            const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    auto &type = sources.back().type;
    bool invalid = false;
    // Unops are only allowed on ints (e.g. ~$x), dereference only on
    // pointers and context (we allow args->field for backwards
    // compatibility)
    if (type.IsBoolTy()) {
      invalid = unop.op != Operator::LNOT;
    } else if (!type.IsIntegerTy() &&
               !((type.IsPtrTy() || type.IsCtxAccess()) && valid_ptr_op)) {
      invalid = true;
    }
    if (invalid) {
      unop.addError() << "The " << opstr(unop)
                      << " operator can not be used on expressions of type '"
                      << type << "'";
      return std::nullopt;
    }

    unop.result_type = CreateNone();
    if (unop.op == Operator::MUL) {
      if (type.IsPtrTy()) {
        unop.result_type = type.GetPointeeTy();
        if (type.IsCtxAccess())
          unop.result_type.MarkCtxAccess();
        unop.result_type.is_internal = type.is_internal;
        unop.result_type.SetAS(type.GetAS());
      } else if (type.IsCStructTy()) {
        // We allow dereferencing "args" with no effect (for backwards
        // compat)
        if (type.IsCtxAccess())
          unop.result_type = type;
        else {
          unop.addError() << "Can not dereference struct/union of type '"
                          << type.GetName() << "'. It is not a pointer.";
        }
      } else {
        unop.addError() << "Can not dereference type '" << type
                        << "'. It is not a pointer.";
      }
    } else if (unop.op == Operator::LNOT) {
      unop.result_type = CreateBool();
    } else if (type.IsPtrTy() && valid_ptr_op) {
      unop.result_type = type;
    } else {
      unop.result_type = CreateInt64();
    }

    return unop.result_type;
  };
}

void TypeGraphPass::visit(VarDeclStatement &decl)
{
  if (find_variable_scope(decl.var->ident) != nullptr) {
    LOG(BUG) << "Variable shadowing should have been caught by now";
  }

  if (!decl.typeof) {
    // If the declaration has no type then we can rely on the assignments to
    // this variable to determine the type. Otherwise we exclusively rely on the
    // type specified in the declaration and ignore the right side (issuing
    // errors later).
    visit(decl.var);
    return;
  }

  visit(decl.typeof);

  auto scope = scope_stack_.back();
  ScopedVariable scoped_var = std::make_pair(scope, decl.var->ident);
  decl_variables_.insert(scoped_var);

  add_to_graph(scoped_var, decl.typeof);
  consumer_to_sources_[scoped_var].callback =
      [this, &decl, scoped_var](const GraphNode &,
                                const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    auto &type = sources.back().type;
    Node *scope = scoped_var.first;
    const auto &var = scoped_var.second;
    auto foundVar = variables_[scope].find(var);

    if (foundVar == variables_[scope].end()) {
      LOG(BUG) << "Variable " << var << " should exist in the variables_ map";
    }

    foundVar->second = type;
    return type;
  };

  visit(decl.var);
}

void TypeGraphPass::visit(Variable &var)
{
  Node *scope = find_variable_scope(var.ident);
  if (scope == nullptr) {
    scope = scope_stack_.back();
  }
  variables_[scope].insert({ var.ident, CreateNone() });

  ScopedVariable scoped_var = std::make_pair(scope, var.ident);

  add_to_graph(&var, scoped_var);
  consumer_to_sources_[&var].callback =
      [&var](const GraphNode &, const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    var.var_type = sources.back().type;
    return var.var_type;
  };

  if (introspection_level_ > 0) {
    introspected_nodes_.insert(scoped_var);
  }
}

void TypeGraphPass::visit(VariableAddr &var_addr)
{
  visit(var_addr.var);
  add_to_graph(&var_addr, var_addr.var);
  consumer_to_sources_[&var_addr].callback =
      [&var_addr](const GraphNode &, const std::vector<ResolvedSource> &sources)
      -> std::optional<SizedType> {
    auto &type = sources.back().type;
    var_addr.var_addr_type = CreatePointer(type, type.GetAS());
    return var_addr.var_addr_type;
  };
}

void TypeGraphPass::resolve_struct_type(SizedType &type, Node &node)
{
  SizedType inner_type = type;
  int pointer_level = 0;
  while (inner_type.IsPtrTy()) {
    inner_type = inner_type.GetPointeeTy();
    pointer_level++;
  }
  if (inner_type.IsCStructTy() && !inner_type.GetStruct()) {
    auto struct_type = bpftrace_.structs.Lookup(inner_type.GetName()).lock();
    if (!struct_type) {
      // Try to find the type as something other than a struct, e.g. 'char' or
      // 'uint64_t'
      auto stype = bpftrace_.btf_->get_stype(inner_type.GetName());
      if (stype.IsNoneTy()) {
        node.addError() << "Cannot resolve unknown type \""
                        << inner_type.GetName() << "\"\n";
      } else {
        type = stype;
        while (pointer_level > 0) {
          type = CreatePointer(type);
          pointer_level--;
        }
      }
    } else {
      type = CreateCStruct(inner_type.GetName(), struct_type);
      while (pointer_level > 0) {
        type = CreatePointer(type);
        pointer_level--;
      }
    }
  }
}

std::optional<SizedType> TypeGraphPass::update_variable_type(
    const ScopedVariable &scoped_var,
    const SizedType &type,
    Node &error_node,
    std::optional<GraphNode> ptr_source)
{
  Node *scope = scoped_var.first;
  const auto &var = scoped_var.second;
  auto foundVar = variables_[scope].find(var);

  if (foundVar == variables_[scope].end()) {
    LOG(BUG) << "Variable " << var << " should exist in the variables_ map";
  }

  if (!check_locked_node(scoped_var, type, error_node, var)) {
    return std::nullopt;
  }

  const auto &current_type = foundVar->second;

  auto promoted = promote_type(current_type, type);
  if (promoted) {
    if (promoted->IsPtrTy() && ptr_source.has_value()) {
      pointer_sources_[scoped_var] = *ptr_source;
    }

    foundVar->second = *promoted;
    return foundVar->second;
  }

  // The types are incompatible, check if it's ok for same-source pointers
  if (ptr_source.has_value() &&
      is_same_pointer_source(scoped_var, *ptr_source, type, current_type)) {
    foundVar->second = type;
    return type;
  }

  error_node.addError() << "Type mismatch for " << var << ": "
                        << "trying to assign value of type '" << type
                        << "' when variable already has a type '"
                        << current_type << "'";
  return foundVar->second;
}

std::optional<SizedType> TypeGraphPass::update_map_value(
    const std::string map_name,
    const SizedType &type,
    Node &error_node,
    std::optional<GraphNode> ptr_source)
{
  if (!maps_.contains(map_name)) {
    LOG(BUG) << "Map should have been added to map";
  }

  auto value_name = get_map_value_name(map_name);

  if (!check_locked_node(value_name, type, error_node, map_name)) {
    return std::nullopt;
  }

  auto &map = maps_[map_name];

  auto promoted = promote_type(map.value_type, type);
  if (promoted) {
    if (promoted->IsPtrTy() && ptr_source.has_value()) {
      pointer_sources_[value_name] = *ptr_source;
    }

    map.value_type = *promoted;
    return promoted;
  }

  // The types are incompatible, check if it's ok for same-source pointers
  if (ptr_source.has_value() &&
      is_same_pointer_source(value_name, *ptr_source, type, map.value_type)) {
    map.value_type = type;
    return type;
  }

  error_node.addError() << "Type mismatch for " << map_name << ": "
                        << "trying to assign value of type '" << type
                        << "' when map already has a type '" << map.value_type
                        << "'";
  return map.value_type;
}

void TypeGraphPass::propagate_resolved_type(const GraphNode &source,
                                            const SizedType &type)
{
  if (type.IsNoneTy()) {
    return;
  }

  auto found = source_to_consumers_.find(source);
  if (found == source_to_consumers_.end()) {
    return;
  }
  for (const auto &consumer : found->second) {
    auto &ts = consumer_to_sources_[consumer];
    auto it = std::find_if(ts.sources.begin(),
                           ts.sources.end(),
                           [&source](const ResolvedSource &rs) {
                             return rs.source == source;
                           });
    if (it == ts.sources.end()) {
      LOG(BUG) << "Graph node not in sources";
    } else {
      it->type = type;
      ++ts.num_resolved;
    }
  }
}

void TypeGraphPass::add_to_graph(const GraphNode &consumer,
                               const GraphNode &source,
                               Node *error_node,
                               std::optional<GraphNode> ptr_source)
{
  source_to_consumers_[source].emplace_back(consumer);
  consumer_to_sources_[consumer].sources.push_back(
      { source, CreateNone(), error_node, std::move(ptr_source) });
}

bool TypeGraphPass::check_locked_node(const GraphNode &node,
                                      const SizedType &type,
                                      Node &error_node,
                                      const std::string &name)
{
  if (auto found_locked = locked_nodes_.find(node);
      found_locked != locked_nodes_.end()) {
    if (!type.FitsInto(found_locked->second)) {
      error_node.addError()
          << "Type mismatch for " << name << ": "
          << "this type has been locked because it was used "
             "in another part of the type graph that was already "
             "resolved (e.g. `sizeof`, `typeinfo`, etc.). The new type '"
          << type << "' doesn't fit into the locked type '"
          << found_locked->second << "'";
      return false;
    }
  }
  return true;
}

GraphNode TypeGraphPass::get_pointer_source(Expression &expr)
{
  if (auto *var_addr = expr.as<VariableAddr>()) {
    Node *addr_scope = find_variable_scope(var_addr->var->ident, true);
    return ScopedVariable{ addr_scope, var_addr->var->ident };
  } else if (auto *map_addr = expr.as<MapAddr>()) {
    return get_map_value_name(map_addr->map->ident);
  } else {
    return &expr.node();
  }
}

bool TypeGraphPass::is_same_pointer_source(const GraphNode &node_key,
                                           const GraphNode &ptr_source,
                                           const SizedType &incoming_type,
                                           const SizedType &current_type)
{
  if (!incoming_type.IsPtrTy() || !current_type.IsPtrTy()) {
    return false;
  }
  auto existing_source = pointer_sources_.find(node_key);
  if (existing_source == pointer_sources_.end()) {
    LOG(BUG) << "Original pointer source should exist";
  }
  return existing_source->second == ptr_source;
}

bool TypeGraphPass::resolve()
{
  for (const auto &rt : resolved_nodes_) {
    propagate_resolved_type(rt.first, rt.second);
  }

  bool made_progress = true;
  while (made_progress) {
    made_progress = false;
    for (auto it = consumer_to_sources_.begin();
         it != consumer_to_sources_.end();) {
      auto &ts = it->second;
      if (ts.sources.size() != ts.num_resolved) {
        ++it;
        continue;
      }
      made_progress = true;
      auto resolved_type = ts.callback(it->first, ts.sources);
      auto source = it->first;
      it = consumer_to_sources_.erase(it);
      if (resolved_type) {
        propagate_resolved_type(source, *resolved_type);
      }
    }
  }

  // Fold expressions like `typeinfo`, `offsetof`, etc.
  IntrospectionFolder(ast_).visit(ast_.root);
  // Fold literals like `comptime (typeof($a).base_ty == "int")`
  fold(ast_);

  return ast_.diagnostics().ok();
}

LockedNodes TypeGraphPass::get_locked_nodes()
{
  LockedNodes locked_nodes;
  for (auto &node : introspected_nodes_) {
    if (auto *scoped_var = std::get_if<ScopedVariable>(&node)) {
      if (auto search_val = variables_[scoped_var->first].find(
              scoped_var->second);
          search_val != variables_[scoped_var->first].end()) {
        if (!search_val->second.IsNoneTy()) {
          locked_nodes.insert({ *scoped_var, search_val->second });
        }
      }
    } else if (auto *map_ident = std::get_if<std::string>(&node)) {
      if (auto search_map = maps_.find(*map_ident); search_map != maps_.end()) {
        if (!search_map->second.key_type.IsNoneTy()) {
          locked_nodes.insert(
              { get_map_key_name(*map_ident), search_map->second.key_type });
        }
        if (!search_map->second.value_type.IsNoneTy()) {
          locked_nodes.insert({ get_map_value_name(*map_ident),
                                search_map->second.value_type });
        }
      }
    }
  }
  return locked_nodes;
}

Node *TypeGraphPass::find_variable_scope(const std::string &var_ident,
                                         bool safe)
{
  for (auto *scope : scope_stack_) {
    if (auto search_val = variables_[scope].find(var_ident);
        search_val != variables_[scope].end()) {
      return scope;
    }
  }
  if (safe) {
    LOG(BUG) << "No scope found for variable: " << var_ident;
  }
  return nullptr;
}

std::string TypeGraphPass::get_map_value_name(const std::string &ident)
{
  return ident + "__val";
}

std::string TypeGraphPass::get_map_key_name(const std::string &ident)
{
  return ident + "__key";
}

std::optional<Expression> IntrospectionFolder::visit(Offsetof &offof)
{
  SizedType cstruct;
  if (std::holds_alternative<SizedType>(offof.record)) {
    cstruct = std::get<SizedType>(offof.record);
  } else {
    cstruct = std::get<Expression>(offof.record).type();
  }

  if (cstruct.IsNoneTy()) {
    return std::nullopt;
  }

  size_t offset = 0;
  for (const auto &field : offof.field) {
    if (!cstruct.IsCStructTy() || !cstruct.HasField(field)) {
      return std::nullopt;
    }
    const auto &f = cstruct.GetField(field);
    offset += f.offset;
    cstruct = f.type;
  }

  return ast_.make_node<Integer>(Location(offof.loc), offset);
}

std::optional<Expression> IntrospectionFolder::visit(Sizeof &szof)
{
  size_t size = 0;
  if (std::holds_alternative<SizedType>(szof.record)) {
    auto &ty = std::get<SizedType>(szof.record);
    if (ty.IsNoneTy()) {
      return std::nullopt;
    }
    size = ty.GetSize();
  } else {
    const auto &ty = std::get<Expression>(szof.record).type();
    if (ty.IsNoneTy()) {
      return std::nullopt;
    }
    size = ty.GetSize();
  }

  return ast_.make_node<Integer>(Location(szof.loc), size);
}

std::optional<Expression> IntrospectionFolder::visit(Typeinfo &typeinfo)
{
  if (typeinfo.typeof->type().IsNoneTy()) {
    return std::nullopt;
  }

  const auto &type = typeinfo.typeof->type();
  // We currently lack a globally-unique enumeration of types. For
  // simplicity, just use the type string with a placeholder identifier.
  auto *id = ast_.make_node<Integer>(typeinfo.loc, 0);
  auto *base_ty = ast_.make_node<String>(typeinfo.loc, to_string(type.GetTy()));
  auto *full_ty = ast_.make_node<String>(typeinfo.loc, typestr(type));

  std::vector<SizedType> elements = { CreateUInt64(),
                                      base_ty->type(),
                                      full_ty->type() };
  std::vector<std::string_view> names = { "btf_id", "base_type", "full_type" };

  auto record_type = CreateRecord(Struct::CreateRecord(elements, names));

  auto record = make_record(
      ast_,
      typeinfo.loc,
      { { "btf_id", id }, { "base_type", base_ty }, { "full_type", full_ty } });

  record->record_type = record_type;

  return record;
}

std::optional<Expression> IntrospectionFolder::visit(Expression &expr)
{
  auto r = Visitor<IntrospectionFolder, std::optional<Expression>>::visit(
      expr.value);
  if (r) {
    expr.value = r->value;
  }
  return std::nullopt;
}

Pass CreateTypeGraphPass()
{
  return Pass::create(
      "TypeGraph",
      [](ASTContext &ast, BPFtrace &b, CDefinitions &c_definitions) {
        IntrinsicTypeResolver(b, c_definitions).visit(ast.root);

        auto type_graph = TypeGraphPass(ast, b, c_definitions);
        type_graph.visit(ast.root);
        bool no_errors = type_graph.resolve();

        auto prev_comptimes = type_graph.get_unresolved_comptimes();
        LockedNodes locked_nodes = type_graph.get_locked_nodes();

        bool has_comptime_error = false;
        while (prev_comptimes.size() > 0 && no_errors) {
          auto next_pass = TypeGraphPass(ast, b, c_definitions, locked_nodes);
          next_pass.visit(ast.root);
          no_errors = next_pass.resolve();

          auto next_comptimes = next_pass.get_unresolved_comptimes();
          if (prev_comptimes == next_comptimes) {
            for (auto *comptime : next_comptimes) {
              comptime->addError() << "Unable to resolve comptime expression";
            }
            has_comptime_error = true;
            break;
          }
          prev_comptimes = next_comptimes;
          locked_nodes = next_pass.get_locked_nodes();
        }

        if (has_comptime_error) {
          return;
        }

        CastCreator(ast, b).visit(ast.root);
      });
};

} // namespace bpftrace::ast
