; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf-pc-linux"

%"struct map_t" = type { ptr, ptr, ptr, ptr }
%"struct map_t.0" = type { ptr, ptr, ptr, ptr }
%"struct map_t.1" = type { ptr, ptr }

@LICENSE = global [4 x i8] c"GPL\00", section "license"
@AT_foo = dso_local global %"struct map_t" zeroinitializer, section ".maps", !dbg !0
@AT_str = dso_local global %"struct map_t.0" zeroinitializer, section ".maps", !dbg !21
@ringbuf = dso_local global %"struct map_t.1" zeroinitializer, section ".maps", !dbg !23

; Function Attrs: nounwind
declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @kprobe_f_1(ptr %0) section "s_kprobe_f_1" !dbg !40 {
entry:
  %"@str_key" = alloca i64, align 8
  %lookup_elem_val = alloca [32 x i8], align 1
  %"@foo_key1" = alloca i64, align 8
  %"@foo_val" = alloca [32 x i8], align 1
  %"@foo_key" = alloca i64, align 8
  %1 = call ptr @llvm.preserve.static.offset(ptr %0)
  %2 = getelementptr i64, ptr %1, i64 14
  %arg0 = load volatile i64, ptr %2, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key")
  store i64 0, ptr %"@foo_key", align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_val")
  %probe_read_kernel = call i64 inttoptr (i64 113 to ptr)(ptr %"@foo_val", i32 32, i64 %arg0)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(ptr @AT_foo, ptr %"@foo_key", ptr %"@foo_val", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_val")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@foo_key1")
  store i64 0, ptr %"@foo_key1", align 8
  %lookup_elem = call ptr inttoptr (i64 1 to ptr)(ptr @AT_foo, ptr %"@foo_key1")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %lookup_elem_val)
  %map_lookup_cond = icmp ne ptr %lookup_elem, null
  br i1 %map_lookup_cond, label %lookup_success, label %lookup_failure

lookup_success:                                   ; preds = %entry
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %lookup_elem_val, ptr align 1 %lookup_elem, i64 32, i1 false)
  br label %lookup_merge

lookup_failure:                                   ; preds = %entry
  call void @llvm.memset.p0.i64(ptr align 1 %lookup_elem_val, i8 0, i64 32, i1 false)
  br label %lookup_merge

lookup_merge:                                     ; preds = %lookup_failure, %lookup_success
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@foo_key1")
  %3 = getelementptr [32 x i8], ptr %lookup_elem_val, i32 0, i64 0
  call void @llvm.lifetime.start.p0(i64 -1, ptr %"@str_key")
  store i64 0, ptr %"@str_key", align 8
  %update_elem2 = call i64 inttoptr (i64 2 to ptr)(ptr @AT_str, ptr %"@str_key", ptr %3, i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %"@str_key")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %lookup_elem_val)
  ret i64 0
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare ptr @llvm.preserve.static.offset(ptr readnone %0) #1

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg %0, ptr nocapture %1) #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly %0, ptr noalias nocapture readonly %1, i64 %2, i1 immarg %3) #3

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly %0, i8 %1, i64 %2, i1 immarg %3) #4

attributes #0 = { nounwind }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nocallback nofree nounwind willreturn memory(argmem: write) }

!llvm.dbg.cu = !{!37}
!llvm.module.flags = !{!39}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "AT_foo", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!2 = !DIFile(filename: "bpftrace.bpf.o", directory: ".")
!3 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 256, elements: !4)
!4 = !{!5, !11, !12, !15}
!5 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !6, size: 64)
!6 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !7, size: 64)
!7 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 32, elements: !9)
!8 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!9 = !{!10}
!10 = !DISubrange(count: 1, lowerBound: 0)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !6, size: 64, offset: 64)
!12 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !2, file: !2, baseType: !13, size: 64, offset: 128)
!13 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !14, size: 64)
!14 = !DIBasicType(name: "int64", size: 64, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !2, file: !2, baseType: !16, size: 64, offset: 192)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !17, size: 64)
!17 = !DICompositeType(tag: DW_TAG_array_type, baseType: !18, size: 256, elements: !19)
!18 = !DIBasicType(name: "int8", size: 8, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DISubrange(count: 32, lowerBound: 0)
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "AT_str", linkageName: "global", scope: !2, file: !2, type: !3, isLocal: false, isDefinition: true)
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "ringbuf", linkageName: "global", scope: !2, file: !2, type: !25, isLocal: false, isDefinition: true)
!25 = !DICompositeType(tag: DW_TAG_structure_type, scope: !2, file: !2, size: 128, elements: !26)
!26 = !{!27, !32}
!27 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !2, file: !2, baseType: !28, size: 64)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 864, elements: !30)
!30 = !{!31}
!31 = !DISubrange(count: 27, lowerBound: 0)
!32 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !2, file: !2, baseType: !33, size: 64, offset: 64)
!33 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!34 = !DICompositeType(tag: DW_TAG_array_type, baseType: !8, size: 8388608, elements: !35)
!35 = !{!36}
!36 = !DISubrange(count: 262144, lowerBound: 0)
!37 = distinct !DICompileUnit(language: DW_LANG_C, file: !2, producer: "bpftrace", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, globals: !38)
!38 = !{!0, !21, !23}
!39 = !{i32 2, !"Debug Info Version", i32 3}
!40 = distinct !DISubprogram(name: "kprobe_f_1", linkageName: "kprobe_f_1", scope: !2, file: !2, type: !41, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !37, retainedNodes: !44)
!41 = !DISubroutineType(types: !42)
!42 = !{!14, !43}
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !18, size: 64)
!44 = !{!45}
!45 = !DILocalVariable(name: "ctx", arg: 1, scope: !40, file: !2, type: !43)
