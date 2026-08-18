; =============================================================================
; loadcfg.asm - IMAGE_LOAD_CONFIG_DIRECTORY64 for a CRT-free /guard:cf image
; -----------------------------------------------------------------------------
; The linker looks for the symbol "_load_config_used" and points the PE load
; config data directory at it.  Without it (LNK4266) the CFG bit is set in
; DllCharacteristics but the loader has no guard metadata.  The guard table /
; count / flags symbols below are synthesized by link.exe when /guard:cf is
; active; the two "nop" routines are the documented safe defaults that the
; OS loader overwrites with the real CFG check routines at load time.
; The loader also rotates the value at __security_cookie at process start.
; =============================================================================

OPTION CASEMAP:NONE

extern start:proc                       ; the only OS-indirect-called target

; GuardFlags: CF_INSTRUMENTED (100h) | CF_FUNCTION_TABLE_PRESENT (400h),
; table stride bits (F0000000h) = 0 -> 4 bytes per entry (plain RVA list).
GUARD_FLAGS_VALUE equ 00000500h

.code

guard_check_icall_nop proc          ; default CFG check: allow (loader replaces)
    ret
guard_check_icall_nop endp

guard_dispatch_icall_nop proc       ; default CFG dispatch: plain indirect jump
    jmp     rax
guard_dispatch_icall_nop endp

.data
public __security_cookie
__security_cookie           dq 2B992DDFA232h        ; loader rotates this
__guard_check_icall_fptr    dq guard_check_icall_nop
__guard_dispatch_icall_fptr dq guard_dispatch_icall_nop

.const
; ---------------------------------------------------------------------------
; Our guard CF function table: every address the OS may call indirectly.
; RtlUserThreadStart dispatches to the image entry point through a CFG-
; checked call, so "start" MUST be here or the process dies with 0xC0000409
; before any of our code runs.  Our own indirect calls (command handlers)
; use plain CALL + DLPV and are not CFG-instrumented, so they are not listed.
; Entries are RVAs, ascending; with a single entry sorting is trivial.
; ---------------------------------------------------------------------------
gfids_table label dword
    dd imagerel start
GFIDS_COUNT equ 1

public _load_config_used
_load_config_used label byte
    dd 140h                         ; Size (full modern struct, 320 bytes)
    dd 0                            ; TimeDateStamp
    dw 0, 0                         ; Major/MinorVersion
    dd 0                            ; GlobalFlagsClear
    dd 0                            ; GlobalFlagsSet
    dd 0                            ; CriticalSectionDefaultTimeout
    dq 0                            ; DeCommitFreeBlockThreshold
    dq 0                            ; DeCommitTotalFreeThreshold
    dq 0                            ; LockPrefixTable
    dq 0                            ; MaximumAllocationSize
    dq 0                            ; VirtualMemoryThreshold
    dq 0                            ; ProcessAffinityMask
    dd 0                            ; ProcessHeapFlags
    dw 0                            ; CSDVersion
    dw 0                            ; DependentLoadFlags
    dq 0                            ; EditList
    dq __security_cookie            ; SecurityCookie
    dq 0                            ; SEHandlerTable (x64: table-based SEH)
    dq 0                            ; SEHandlerCount
    dq __guard_check_icall_fptr     ; GuardCFCheckFunctionPointer
    dq __guard_dispatch_icall_fptr  ; GuardCFDispatchFunctionPointer
    dq gfids_table                  ; GuardCFFunctionTable (VA)
    dq GFIDS_COUNT                  ; GuardCFFunctionCount
    dd GUARD_FLAGS_VALUE            ; GuardFlags
    dw 0, 0                         ; CodeIntegrity.Flags/Catalog
    dd 0                            ; CodeIntegrity.CatalogOffset
    dd 0                            ; CodeIntegrity.Reserved
    dq 0                            ; GuardAddressTakenIatEntryTable
    dq 0                            ; GuardAddressTakenIatEntryCount
    dq 0                            ; GuardLongJumpTargetTable
    dq 0                            ; GuardLongJumpTargetCount
    dq 0                            ; DynamicValueRelocTable
    dq 0                            ; CHPEMetadataPointer
    dq 0                            ; GuardRFFailureRoutine
    dq 0                            ; GuardRFFailureRoutineFunctionPointer
    dd 0                            ; DynamicValueRelocTableOffset
    dw 0                            ; DynamicValueRelocTableSection
    dw 0                            ; Reserved2
    dq 0                            ; GuardRFVerifyStackPointerFunctionPointer
    dd 0                            ; HotPatchTableOffset
    dd 0                            ; Reserved3
    dq 0                            ; EnclaveConfigurationPointer
    dq 0                            ; VolatileMetadataPointer
    dq 0                            ; GuardEHContinuationTable
    dq 0                            ; GuardEHContinuationCount
    dq 0                            ; GuardXFGCheckFunctionPointer
    dq 0                            ; GuardXFGDispatchFunctionPointer
    dq 0                            ; GuardXFGTableDispatchFunctionPointer
    dq 0                            ; CastGuardOsDeterminedFailureMode
    dq 0                            ; GuardMemcpyFunctionPointer

end
