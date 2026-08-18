; =============================================================================
; compress.asm - XPRESS block compression via the Windows Compression API
; -----------------------------------------------------------------------------
; Inbox Cabinet.dll (Windows 8+).  One-shot buffer compress/decompress used to
; build a simple framed block stream:  [u32 orig_len][u32 payload_len][payload]
; where payload_len < orig_len means XPRESS-compressed, payload_len == orig_len
; means stored (compression did not help).  pack.asm does the framing.
;
;   comp_init()   -> eax 0 ok / 1 fail
;   comp_block(rcx=src, rdx=srclen, r8=dst, r9=dstcap) -> eax = out bytes (0 fail)
;   comp_close()
;
; DECOMPRESSION IS NOT HERE.  It used to be - decomp_init/decomp_block/
; decomp_close, one handle in a global - and it served exactly one caller, the
; route that inflated a whole archive into a temporary tar before extracting it.
; That route is gone (docs/V5_WORK.md, step A2): entries are decoded straight
; out of the container by estream.asm, which creates a decompressor PER CONTEXT
; rather than sharing one, because two streams can be open at once.
; =============================================================================

include macros.inc

extern CreateCompressor:proc
extern Compress:proc
extern CloseCompressor:proc

COMPRESS_ALGORITHM_XPRESS equ 3

.data?
g_comp_handle   dq ?

.code

public comp_init
comp_init proc frame
    FRAME_PROLOG 48
    WINCALL CreateCompressor, COMPRESS_ALGORITHM_XPRESS, 0, addr g_comp_handle
    test    eax, eax
    jz      ci_fail
    xor     eax, eax
    jmp     ci_done
ci_fail:
    mov     eax, 1
ci_done:
    FRAME_EPILOG
    ret
comp_init endp

public comp_close
comp_close proc frame
    FRAME_PROLOG 32
    mov     rcx, qword ptr [g_comp_handle]
    xIFT rcx
        WINCALL CloseCompressor, rcx
        mov     qword ptr [g_comp_handle], 0
    xENDIF
    FRAME_EPILOG
    ret
comp_close endp

; comp_block(rcx=src, rdx=srclen, r8=dst, r9=dstcap) -> eax = compressed bytes
; (0 on failure -> caller stores raw)
public comp_block
comp_block proc frame
    FRAME_PROLOG 96
    ; [rbp-24]=outsize  [rbp-32]=src [rbp-40]=srclen [rbp-48]=dst [rbp-56]=dstcap
    mov     qword ptr [rbp-32], rcx
    mov     qword ptr [rbp-40], rdx
    mov     qword ptr [rbp-48], r8
    mov     qword ptr [rbp-56], r9
    mov     qword ptr [rbp-24], 0
    ; Compress(handle, src, srclen, dst, dstcap, &outsize)
    WINCALL Compress, qword ptr [g_comp_handle], qword ptr [rbp-32], qword ptr [rbp-40], qword ptr [rbp-48], qword ptr [rbp-56], addr rbp-24
    test    eax, eax
    jz      cb_fail
    mov     eax, dword ptr [rbp-24]
    jmp     cb_done
cb_fail:
    xor     eax, eax
cb_done:
    FRAME_EPILOG
    ret
comp_block endp

end
