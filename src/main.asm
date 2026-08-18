; =============================================================================
; main.asm - entry point, CPU gate, command-line parsing, dispatch
; =============================================================================
; Startup order (deliberate):
;   1. cpu_gate        - raw frame; sets g_cpu_features (rng_fill reads RDSEED)
;   2. hardening_init  - raw frame; canary + shadow stack become live
;   3. con_init        - first FRAME_PROLOG-protected call
;   4. iat_lockdown    - IAT pages -> read-only BEFORE any user input is parsed
;   5. parse_cmdline / validate / dispatch (DLPV-guarded indirect call)
; =============================================================================

include macros.inc

extern GetCommandLineW:proc
extern ExitProcess:proc
extern WideCharToMultiByte:proc
extern GetStdHandle:proc
extern WriteFile:proc

STD_OUTPUT_HANDLE_   equ -11

; ---------------------------------------------------------------------------
; DBG ch - startup breadcrumb (only assembled with /DDBG_TRACE).  Prints one
; character to stdout, preserving no volatile registers (caller must not rely
; on them across a DBG point).  Used to localize early-startup faults.
; ---------------------------------------------------------------------------
DBG macro ch
ifdef DBG_TRACE
    mov     al, ch
    call    dbg_putc
endif
endm

extern hardening_init:proc
extern iat_lockdown:proc
extern secure_zero:proc
extern secmem_wipe_all:proc             ; secmem.asm: wipe + unlock all secrets
extern run_selftest:proc
extern do_encrypt:proc
extern do_decrypt:proc
extern do_verify:proc
extern do_list:proc
extern do_add:proc
ifdef TEST_IO
extern pfx_stage:proc
extern do_estream:proc
extern do_dataobj:proc
endif
extern do_zip_add:proc
extern do_delete:proc
extern do_hash:proc
extern do_bench:proc
extern do_unzip:proc
extern do_zip:proc
extern log_result:proc
extern apply_policy_locks:proc          ; gui.asm: re-assert HKLM policy post-parse
ifdef DBG_TRACE
extern cmd_redteam:proc                 ; fault-injection self-test (redteam.asm)
extern cmd_secdesk:proc                 ; private-desktop smoke test (secdesk.asm)
endif

ENC_VAR              equ 0FFFFFFFEh  ; CMDENT.pos_args sentinel: variable (>=1)
extern con_init:proc
extern print_a:proc
extern print_err:proc
extern print_wze:proc                    ; names the offending argument on stderr

CP_UTF8              equ 65001
WC_ERR_INVALID_CHARS equ 80h

ARGBUF_CHARS         equ 20000h      ; total UTF-16 units for all parsed args
                                    ; (holds two extended-length paths + options)

; -----------------------------------------------------------------------------
; Parsed configuration (single-threaded; statics are simplest and safest here)
; -----------------------------------------------------------------------------
.data
public g_cfg_in, g_cfg_out, g_cfg_passlen, g_cfg_t, g_cfg_m
public g_cfg_pwminlen, g_cfg_pwminclasses
g_argc          dd 0
g_cfg_in        dq 0                ; -> UTF-16 input path  (into g_argbuf)
g_cfg_out       dq 0                ; -> UTF-16 output path (into g_argbuf)
g_cfg_passlen   dd 0                ; UTF-8 password length in bytes
g_cfg_t         dd ARGON2_DEF_T
g_cfg_m         dd ARGON2_DEF_M_KIB
g_cfg_pwminlen      dd 12           ; password policy: min length (code points)
g_cfg_pwminclasses  dd 3            ; password policy: min distinct char classes
public g_cfg_compress, g_cfg_compress_set
g_cfg_compress      dd 0            ; pack: 0 = store, 1 = XPRESS compress
g_cfg_compress_set  dd 0            ; 0 = use the size-based default; 1 = explicit
public g_cfg_json
g_cfg_json          dd 0            ; hash: 1 = emit JSON instead of text
public g_cfg_loglevel
g_cfg_loglevel      dd 0            ; log verbosity (0 = none/off by default; see log.asm)
public g_cfg_logfile
g_cfg_logfile       dq 0            ; --log-file PATH override (0 = default path)
public g_cfg_securedesk
; 1 = type the password on a private desktop (secdesk.asm), 0 = an ordinary
; modal on the interactive desktop.  Defaults ON, and the MSI writes it to HKLM
; so it is enforced rather than merely defaulted.  Turning it off restores the
; surface that lets Myrkr be driven headlessly by window messages - the cost is
; set out in manifest section 14.
g_cfg_securedesk    dd 1

.data?
public g_cfg_pass, g_positionals, g_poscount
g_argv          dq MAX_ARGS dup (?)
g_argbuf        dw ARGBUF_CHARS dup (?)
g_cfg_pass      db MAX_PASSWORD_BYTES+1 dup (?)
g_positionals   dq MAX_ARGS dup (?)  ; -> UTF-16 positional argument strings
g_poscount      dq ?                 ; number of positionals

; -----------------------------------------------------------------------------
.const
msg_usage label byte
    db "Myrkr - AES-256-GCM file encryption (Argon2id KDF)",13,10
    db 13,10
ifdef TEST_IO
    db "  myrkr encrypt INPUT [INPUT...] -o OUTPUT -p PASSWORD [-m MIB] [-t PASSES]",13,10
    db "                 (multiple inputs or a folder are archived automatically;",13,10
    db "                  add --compress for XPRESS; default is store)",13,10
    db "  myrkr decrypt INPUT [-o OUTPUT] -p PASSWORD",13,10
    db "                 (an archive container extracts to a folder; -o optional)",13,10
    db "  myrkr verify  INPUT -p PASSWORD",13,10
    db "  myrkr zip     INPUT [INPUT...] -o OUTPUT.zip -p PASSWORD   (WinZip AES-256)",13,10
    db "  myrkr unzip   INPUT.zip [-o OUTDIR] -p PASSWORD   (WinZip AES-128/192/256)",13,10
else
    db "  encrypting and decrypting are done in the window, not here: the",13,10
    db "  password is typed on a private desktop that a script cannot reach.",13,10
    db "  Right-click a file or folder -> Encrypt with Myrkr, or run: myrkr",13,10
    db 13,10
endif
    db "  myrkr hash    FILE|FOLDER [--json] [-o OUTFILE]",13,10
    db "                 (a folder hashes every file; path is relative to it)",13,10
    db "  myrkr selftest",13,10
    db "  myrkr bench",13,10
    db 13,10
ifdef TEST_IO
    db "  encrypt password policy (default: min 12 chars, 3 of 4 classes):",13,10
    db "    [--min-len N] [--min-classes K]  (K = 0..4)   [--no-policy]",13,10
    db "    classes = uppercase, lowercase, digit, symbol",13,10
    db 13,10
endif
    db "  audit log (any command, off by default): [--log LEVEL] [--log-file PATH]",13,10
    db "    LEVEL = none | error | warning | full | debug   (default: none)",13,10
    db "    default PATH = %LOCALAPPDATA%\Myrkr\myrkr.log",13,10
msg_usage_len equ $ - msg_usage
CSTR msg_nocpu,    "error: CPU lacks required features (AES-NI, PCLMULQDQ, SSE4.1)",13,10
CSTR msg_badpass,  "error: password must be 1..1024 UTF-8 bytes (valid UTF-16 input)",13,10
CSTR msg_badnum,   "error: numeric argument out of range",13,10
; An argument that begins with '-' and matched no option used to become an INPUT
; PATH.  So "--stor" (meaning "--store") named a file, and what happened next
; depended on whether a file of that name happened to exist:
;   it does not (the usual case) -> "error: I/O failure", which blames the disk
;                                   for a typo and names nothing
;   it does                      -> EXIT 0.  The option is silently ignored AND
;                                   THAT FILE IS ADDED TO THE ARCHIVE.
; The second is measured rather than supposed: with a file called "--stor"
; present, `encrypt in -o out.mrk --stor` succeeded and listed it as an entry.
CSTR msg_badopt,   "error: unrecognized option: "
CSTR msg_badopt2,  13,10,"       run 'myrkr --help' for the options this command takes.",13,10,"       to name an input that really does begin with '-', write it as .\-name",13,10
CSTR msg_st_ok,    "all self-tests passed",13,10
CSTR msg_st_fail,  "SELFTEST FAILURE",13,10
ifndef TEST_IO
CSTR msg_no_cli1,  "error: this command is not available from the command line.",13,10
CSTR msg_no_cli2,  "  Myrkr takes the password on a private desktop, so encryption and",13,10
CSTR msg_no_cli3,  "  decryption are driven from the window - not from a script.",13,10
CSTR msg_no_cli4,  "  Right-click a file or folder and choose Encrypt with Myrkr, or",13,10
CSTR msg_no_cli5,  "  double-click a .mrk container. hash/selftest/bench still work here.",13,10
endif

WSTR w_encrypt,  <encrypt>
WSTR w_decrypt,  <decrypt>
WSTR w_verify,   <verify>
WSTR w_list,     <list>
WSTR w_add,      <add>
WSTR w_zipadd,   <zipadd>
WSTR w_delete,   <delete>
WSTR w_zip,      <zip>
WSTR w_unzip,    <unzip>
WSTR w_hash,     <hash>
WSTR w_selftest, <selftest>
WSTR w_bench,    <bench>
ifdef TEST_IO
; "estream" drives the IStream in estream.asm directly - construct, Read,
; Release - with no drag and no shell involved.  Test-only for the same reason
; -p is: a release binary has no business carrying a way to script extraction.
WSTR w_estream,  <estream>
WSTR w_dataobj,  <dataobj>
endif
ifdef DBG_TRACE
WSTR w_redteam,  <redteam>
WSTR w_secdesk,  <secdesk>
endif
ifdef TEST_IO
; Marker so a test build is identifiable from the outside.  It exists only to be
; found: tools\make_msi.ps1 scans the image for it and refuses to package a
; binary that accepts a password on the command line.  Nothing else about the
; file distinguishes one - same name, same version resource, same icons - and a
; test build shipped by accident would hand every user the automation surface
; the release build exists to withhold.
WSTR w_testio_marker, <MYRKR_TEST_IO_BUILD>
public w_testio_marker
endif
ifdef TEST_IO
; "-p" exists ONLY in a test build.  A release binary has no way to take a
; password from the command line at all - that surface is what would let an
; authorized-but-abused Myrkr be scripted across an estate.
WSTR w_opt_p,    <-p>
; "--stage <n>:<folder>" is likewise test-only.  The staged layout is a GUI
; gesture - you drop a file onto a folder row - and there is no reason for a
; release binary to carry a way to script it.  It exists so that the NAMING
; half can be tested before any of the tree work it depends on, which is the
; order docs/STAGED_LAYOUT.md argues for.
WSTR w_opt_stage, <--stage>
endif
WSTR w_opt_o,    <-o>
WSTR w_opt_out,  <--out>
WSTR w_opt_m,    <-m>
WSTR w_opt_t,    <-t>
WSTR w_opt_minlen,     <--min-len>
WSTR w_opt_minclasses, <--min-classes>
WSTR w_opt_nopolicy,   <--no-policy>
WSTR w_opt_compress,   <--compress>
WSTR w_opt_store,      <--store>
WSTR w_opt_json,       <--json>
WSTR w_opt_log,        <--log>
WSTR w_opt_logfile,    <--log-file>
WSTR w_lvl_none,       <none>
WSTR w_lvl_error,      <error>
WSTR w_lvl_warning,    <warning>
WSTR w_lvl_full,       <full>
WSTR w_lvl_debug,      <debug>

; command table: UTF-16 name ptr | handler ptr | required positional args
CMDENT struct
    name_ptr    dq ?
    handler     dq ?
    pos_args    dd ?                ; positional (non-option) args after command
    needs_pass  dd ?                ; 1 if -p is mandatory
CMDENT ends

cmd_table label CMDENT
    CMDENT { w_encrypt,  cmd_encrypt,  ENC_VAR, 1 }   ; >=1 input, -o output
    CMDENT { w_decrypt,  cmd_decrypt,  1, 1 }          ; 1 container, -o optional
    CMDENT { w_verify,   cmd_verify,   1, 1 }
    CMDENT { w_list,     cmd_list,     1, 1 }   ; container -> its inventory
    CMDENT { w_delete,   cmd_delete,   ENC_VAR, 1 } ; container + names to remove
    CMDENT { w_add,      cmd_add,      ENC_VAR, 1 } ; container + inputs to append
    CMDENT { w_zipadd,   cmd_zipadd,   ENC_VAR, 0 } ; zip + inputs (-p only if encrypted)
    CMDENT { w_zip,      cmd_zip,      ENC_VAR, 0 }     ; >=1 input -> .zip (-p optional; none = unencrypted)
    CMDENT { w_unzip,    cmd_unzip,    1, 0 }          ; .zip, -o optional, -p only if encrypted
; The nine entries ABOVE are the password-taking verbs.  Release builds refuse
; them (dispatch, below) - keep them first and keep this count in step.
CMD_NOCLI equ 9
    CMDENT { w_hash,     cmd_hash,     1, 0 }
    CMDENT { w_selftest, cmd_selftest, 0, 0 }
    CMDENT { w_bench,    cmd_bench,    0, 0 }
ifdef TEST_IO
; Deliberately NOT among the nine above: it exists only in a test build, so it
; needs no release refusal, and putting it there would move CMD_NOCLI.
    CMDENT { w_estream,  cmd_estream,  1, 1 }   ; container, -o outdir
    CMDENT { w_dataobj,  cmd_dataobj,  ENC_VAR, 1 } ; container [selection], -o outdir
endif
ifdef DBG_TRACE
    CMDENT { w_redteam,  cmd_redteam,  1, 0 }   ; fault-injection self-test
    CMDENT { w_secdesk,  cmd_secdesk,  0, 0 }   ; private-desktop smoke test
endif
; DERIVED, never counted by hand.  This was two hardcoded numbers, and adding a
; verb without bumping them does not fail to build and does not fail visibly:
; the entries past the count simply stop existing.  The table is searched in
; order, so it is always the LAST verbs that vanish, and they vanish silently.
;
; Adding `add` dropped `secdesk`, which nothing tests, so nobody noticed.
; Adding `zipadd` dropped `redteam` - and every redteam case then HUNG rather
; than reporting an unknown verb, which read as "the new zip code hangs the
; fault-injection suite" and cost a full debugging round to trace back here.
; In release it had also pushed `hash` and `bench` off the end.
;
; The count is now the table's own length, so a verb cannot be added without it.
CMD_COUNT equ ($ - cmd_table) / (sizeof CMDENT)

.data?
ifdef DBG_TRACE
dbg_char    db ?
dbg_written dd ?
endif
ifdef TEST_IO
g_stagebuf  db 1024 dup (?)     ; --stage's folder, converted to UTF-8
endif

.code

ifdef DBG_TRACE
; al = character to print; clobbers volatiles only
dbg_putc proc
    mov     byte ptr [dbg_char], al
    push    rbp
    mov     rbp, rsp
    sub     rsp, 64
    WINCALL GetStdHandle, STD_OUTPUT_HANDLE_
    ; handle through memory: WINCALL emits the 5th argument first and would use
    ; rax as scratch if it were ever a 64-bit memory operand rather than 0
    mov     qword ptr [rbp-8], rax
    WINCALL WriteFile, qword ptr [rbp-8], addr dbg_char, 1, addr dbg_written, 0
    mov     rsp, rbp
    pop     rbp
    ret
dbg_putc endp
endif

; =============================================================================
; ff_trap - central fail handler.  ecx = fail code (FF_*).  Never returns.
; Release build: immediate __fastfail (int 29h) - non-catchable termination.
; Debug build  : prints "FF" + 4 hex digits of the code so a fault can be
;                attributed to the exact check that fired, then exits.
; =============================================================================
public ff_trap
ff_trap proc
ifdef DBG_TRACE
    mov     r15d, ecx                   ; preserve code (r15 nonvolatile, unused)
    and     rsp, -16                    ; realign (we never return from here)
    mov     al, 'F'
    call    dbg_putc
    mov     al, 'F'
    call    dbg_putc
    mov     ecx, 12                     ; print 4 nibbles, high to low
ff_hexloop:
    sub     ecx, 4
    mov     eax, r15d
    shr     eax, cl
    and     eax, 0Fh
    cmp     al, 10
    jb      ff_dec
    add     al, 'a' - 10
    jmp     ff_emit
ff_dec:
    add     al, '0'
ff_emit:
    push    rcx
    call    dbg_putc
    pop     rcx
    test    ecx, ecx
    jnz     ff_hexloop
    mov     al, 13
    call    dbg_putc
    mov     al, 10
    call    dbg_putc
    ; encode the FF code into the exit status so a test harness can attribute the
    ; fault even when stdout is redirected away by AttachConsole (0xFADE<code>).
    mov     eax, r15d
    or      eax, 0FADE0000h
    WINCALL ExitProcess, eax
endif
    int     29h                         ; release: real fast-fail
ff_trap endp

; =============================================================================
; cpu_gate - detect required/optional CPU features into g_cpu_features.
; Raw frame (runs before hardening_init).  Returns eax=1 if required set ok.
; Required: AES-NI, PCLMULQDQ, SSE4.1.  Optional: SHA-NI, AVX2, RDSEED.
; =============================================================================
cpu_gate proc frame
    push    rbx                         ; cpuid clobbers rbx (non-volatile)
    .pushreg rbx
    .endprolog
    xor     r10d, r10d                  ; feature accumulator

    xor     eax, eax                    ; leaf 0: highest supported leaf
    xor     ecx, ecx
    cpuid
    mov     r9d, eax                    ; r9d = max leaf

    mov     eax, 1
    xor     ecx, ecx
    cpuid
    test    ecx, 1 SHL 25               ; AES-NI
    jz      @F
    or      r10d, CPUF_AESNI
@@: test    ecx, 1 SHL 1                ; PCLMULQDQ
    jz      @F
    or      r10d, CPUF_PCLMUL
@@: test    ecx, 1 SHL 19               ; SSE4.1
    jz      @F
    or      r10d, CPUF_SSE41
@@:
    cmp     r9d, 7                      ; leaf 7 may not exist on old CPUs
    jb      cg_store
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    test    ebx, 1 SHL 29               ; SHA-NI
    jz      @F
    or      r10d, CPUF_SHANI
@@: test    ebx, 1 SHL 5                ; AVX2
    jz      @F
    or      r10d, CPUF_AVX2
@@: test    ebx, 1 SHL 18               ; RDSEED
    jz      @F
    or      r10d, CPUF_RDSEED
@@:
cg_store:
    mov     dword ptr [g_cpu_features], r10d
    mov     eax, r10d
    and     eax, CPUF_AESNI or CPUF_PCLMUL or CPUF_SSE41
    cmp     eax, CPUF_AESNI or CPUF_PCLMUL or CPUF_SSE41
    sete    al
    movzx   eax, al
    pop     rbx
    ret
cpu_gate endp

; =============================================================================
; wstr_eq(rcx, rdx) -> eax = 1 if equal NUL-terminated UTF-16 strings
; =============================================================================
public wstr_eq
wstr_eq proc
    xor     r10d, r10d
we_loop:
    movzx   eax, word ptr [rcx+r10*2]
    movzx   r11d, word ptr [rdx+r10*2]
    cmp     eax, r11d
    jne     we_no
    test    eax, eax
    jz      we_yes
    inc     r10
    cmp     r10, MAX_PATH_CHARS         ; bound the scan
    jb      we_loop
we_no:
    xor     eax, eax
    ret
we_yes:
    mov     eax, 1
    ret
wstr_eq endp

; =============================================================================
; parse_loglevel(rcx = wide LEVEL) -> eax = level 0..4, or -1 if unrecognized.
; none=0 error=1 warning=2 full=3 debug=4
; =============================================================================
parse_loglevel proc frame
    FRAME_PROLOG 32
    mov     qword ptr [rbp-24], rcx
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_none]
    call    wstr_eq
    test    eax, eax
    jnz     pl_0
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_error]
    call    wstr_eq
    test    eax, eax
    jnz     pl_1
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_warning]
    call    wstr_eq
    test    eax, eax
    jnz     pl_2
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_full]
    call    wstr_eq
    test    eax, eax
    jnz     pl_3
    mov     rcx, qword ptr [rbp-24]
    lea     rdx, [w_lvl_debug]
    call    wstr_eq
    test    eax, eax
    jnz     pl_4
    mov     eax, -1
    jmp     pl_done
pl_0:
    xor     eax, eax
    jmp     pl_done
pl_1:
    mov     eax, 1
    jmp     pl_done
pl_2:
    mov     eax, 2
    jmp     pl_done
pl_3:
    mov     eax, 3
    jmp     pl_done
pl_4:
    mov     eax, 4
pl_done:
    FRAME_EPILOG
    ret
parse_loglevel endp

; =============================================================================
; wstr_to_u32(rcx) -> eax = value, edx = 1 ok / 0 bad
; Decimal only, overflow-checked, rejects empty and non-digits.
; =============================================================================
wstr_to_u32 proc
    xor     eax, eax                    ; value
    xor     r10d, r10d                  ; index
    movzx   r11d, word ptr [rcx]
    test    r11d, r11d
    jz      wu_bad                      ; empty string
wu_loop:
    movzx   r11d, word ptr [rcx+r10*2]
    test    r11d, r11d
    jz      wu_ok
    sub     r11d, '0'
    cmp     r11d, 9
    ja      wu_bad                      ; non-digit
    imul    rax, rax, 10                ; 64-bit math, then range check
    add     rax, r11
    mov     rdx, rax
    shr     rdx, 32
    jnz     wu_bad                      ; exceeded 32 bits
    inc     r10
    cmp     r10, 12
    jb      wu_loop
wu_bad:
    xor     eax, eax
    xor     edx, edx
    ret
wu_ok:
    mov     edx, 1
    ret
wstr_to_u32 endp

; =============================================================================
; parse_cmdline - tokenize GetCommandLineW into g_argv/g_argc using the
; standard Windows quoting rules (incl. backslash-quote and "" handling).
; Every write into g_argbuf is bounds-checked.  Returns nothing; overlong
; input fastfails (it cannot occur from a legitimate shell).
; =============================================================================
public parse_cmdline
parse_cmdline proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] = cursor (source), using regs:
    ;   rsi-like roles via r8 = src cursor, r9 = dst index (units),
    ;   r10 = scratch, r11d = in-quotes flag, rbx avoided (volatile only)

    WINCALL GetCommandLineW
    mov     r8, rax                     ; r8 = source cursor
    xor     r9d, r9d                    ; r9 = output index into g_argbuf
    mov     dword ptr [g_argc], 0

    ; ---- program name = argv[0] (simplified rule: only '"' toggles) ----------
    ; We STORE it so the rest of the program can use C-style indexing:
    ; argv[0]=exe, argv[1]=command, argv[2..]=positional/option args.
    lea     r10, [g_argbuf]
    lea     r11, [g_argv]
    mov     qword ptr [r11], r10        ; argv[0] -> start of buffer
    mov     dword ptr [g_argc], 1
    movzx   eax, word ptr [r8]
    cmp     eax, '"'
    jne     pc_prog_plain
    add     r8, 2                       ; consume opening quote
pc_prog_q:
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      pc_prog_term
    add     r8, 2
    cmp     eax, '"'
    je      pc_prog_term                ; closing quote consumed
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], ax
    inc     r9
    jmp     pc_prog_q
pc_prog_plain:
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      pc_prog_term
    cmp     eax, ' '
    je      pc_prog_term
    cmp     eax, 9                      ; tab
    je      pc_prog_term
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], ax
    inc     r9
    add     r8, 2
    jmp     pc_prog_plain
pc_prog_term:
    BOUND_CHECK r9, ARGBUF_CHARS
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], 0      ; NUL-terminate argv[0]
    inc     r9

pc_args_start:
    ; ---- token loop ---------------------------------------------------------
pc_next_token:
    ; skip whitespace
pc_skip_ws:
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      pc_done
    cmp     eax, ' '
    je      pc_ws
    cmp     eax, 9
    jne     pc_token_begin
pc_ws:
    add     r8, 2
    jmp     pc_skip_ws

pc_token_begin:
    ; register the token start in g_argv
    mov     eax, dword ptr [g_argc]
    cmp     eax, MAX_ARGS               ; arg table full?
    jae     pc_done                     ; yes - ignore any remaining tokens
    lea     r10, [g_argbuf]
    lea     r10, [r10+r9*2]
    lea     r11, [g_argv]
    mov     qword ptr [r11+rax*8], r10
    inc     eax
    mov     dword ptr [g_argc], eax
    xor     r11d, r11d                  ; in-quotes = 0

pc_char:
    movzx   eax, word ptr [r8]
    test    eax, eax
    jz      pc_token_end
    cmp     eax, '\'
    je      pc_backslashes
    cmp     eax, '"'
    je      pc_quote
    ; whitespace ends the token only when not inside quotes
    test    r11d, r11d
    jnz     pc_emit
    cmp     eax, ' '
    je      pc_token_end
    cmp     eax, 9
    je      pc_token_end
pc_emit:
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], ax
    inc     r9
    add     r8, 2
    jmp     pc_char

pc_backslashes:
    ; count consecutive backslashes
    xor     edx, edx                    ; count
pc_bs_count:
    movzx   eax, word ptr [r8]
    cmp     eax, '\'
    jne     pc_bs_decide
    inc     edx
    add     r8, 2
    jmp     pc_bs_count
pc_bs_decide:
    cmp     eax, '"'
    je      pc_bs_quote
    ; not followed by quote: emit all backslashes literally
pc_bs_emit_all:
    test    edx, edx
    jz      pc_char
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], '\'
    inc     r9
    dec     edx
    jmp     pc_bs_emit_all
pc_bs_quote:
    ; 2n -> n backslashes, quote is delimiter; 2n+1 -> n backslashes + literal "
    mov     eax, edx
    shr     eax, 1                      ; n = count/2
pc_bs_emit_half:
    test    eax, eax
    jz      pc_bs_half_done
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], '\'
    inc     r9
    dec     eax
    jmp     pc_bs_emit_half
pc_bs_half_done:
    test    edx, 1
    jz      pc_char                     ; even: leave quote for pc_quote
    ; odd: consume the quote as a literal character
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], '"'
    inc     r9
    add     r8, 2                       ; consume the quote
    jmp     pc_char

pc_quote:
    add     r8, 2                       ; consume quote
    test    r11d, r11d
    jz      pc_quote_open
    ; closing quote - check for "" (literal quote) rule
    movzx   eax, word ptr [r8]
    cmp     eax, '"'
    jne     pc_quote_close
    BOUND_CHECK r9, ARGBUF_CHARS-1
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], '"'
    inc     r9
    add     r8, 2
    jmp     pc_char
pc_quote_open:
    mov     r11d, 1
    jmp     pc_char
pc_quote_close:
    xor     r11d, r11d
    jmp     pc_char

pc_token_end:
    ; NUL-terminate the token
    BOUND_CHECK r9, ARGBUF_CHARS
    lea     r10, [g_argbuf]
    mov     word ptr [r10+r9*2], 0
    inc     r9
    movzx   eax, word ptr [r8]
    test    eax, eax
    jnz     pc_next_token
pc_done:
    FRAME_EPILOG
    ret
parse_cmdline endp

; =============================================================================
; collect_options - walk g_argv[2..] for the active command.
;   rcx -> CMDENT for the command
; Fills g_cfg_in / g_cfg_out / g_cfg_pass / g_cfg_m / g_cfg_t.
; Returns eax = exit code (EXIT_OK if all good).
; =============================================================================
collect_options proc frame
    ; 160, not 96: --stage converts its folder with WideCharToMultiByte, which
    ; takes EIGHT arguments, so its outgoing area is 64 bytes and has to sit
    ; BELOW the deepest local rather than through it.  At 96 the spill landed
    ; exactly on the three locals the option parses into.
    FRAME_PROLOG 160
    ; locals:
    ;   [rbp-24]  CMDENT ptr
    ;   [rbp-32]  arg index
    ;   [rbp-40]  positional count seen
    ;   [rbp-48]  wide password ptr (0 if none)

    mov     qword ptr [rbp-24], rcx
    mov     qword ptr [rbp-32], 2       ; argv[0]=exe, argv[1]=command
    mov     qword ptr [rbp-40], 0
    mov     qword ptr [rbp-48], 0
    mov     qword ptr [g_cfg_in], 0
    mov     qword ptr [g_cfg_out], 0

co_loop:
    mov     rax, qword ptr [rbp-32]
    mov     r10d, dword ptr [g_argc]
    cmp     rax, r10
    jae     co_check

    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]  ; current arg

ifdef TEST_IO
    ; ---- "-p <password>" (test builds only) ---------------------------------
    lea     rdx, [w_opt_p]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_p
    ; ---- "--stage <n>:<folder>" (test builds only) --------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_stage]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_stage
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
endif
    ; ---- "-o <output>" / "--out <output>" -----------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_o]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_o
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_out]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_o
    ; ---- "-m <MiB>" ---------------------------------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_m]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_m
    ; ---- "-t <passes>" ------------------------------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_t]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_t
    ; ---- "--min-len <N>" ----------------------------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_minlen]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_minlen
    ; ---- "--min-classes <K>" ------------------------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_minclasses]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_minclasses
    ; ---- "--no-policy" (flag) -----------------------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_nopolicy]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_nopolicy
    ; ---- "--compress" / "--store" (flags) -----------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_compress]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_compress
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_store]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_store
    ; ---- "--json" (flag) ----------------------------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_json]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_json
    ; ---- "--log LEVEL" ------------------------------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_log]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_log
    ; ---- "--log-file PATH" --------------------------------------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    lea     rdx, [w_opt_logfile]
    call    wstr_eq
    test    eax, eax
    jnz     co_take_logfile

    ; ---- positional: store into g_positionals[poscount] ---------------------
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    ; AN ARGUMENT THAT LOOKS LIKE AN OPTION AND MATCHED NONE IS AN ERROR, not an
    ; input path.  It used to fall through to here - see msg_badopt above for
    ; what that cost, including the case where the typo SUCCEEDS and quietly
    ; takes a file into the archive with it.
    ;
    ; Refusing here and not earlier is deliberate: an option's VALUE is consumed
    ; by co_next_arg inside each handler, so a value that begins with '-' never
    ; reaches this point and is still accepted.
    movzx   edx, word ptr [rcx]
    cmp     edx, '-'
    je      co_badopt
    mov     rdx, qword ptr [rbp-40]     ; poscount
    BOUND_CHECK rdx, MAX_ARGS
    lea     r11, [g_positionals]
    mov     qword ptr [r11+rdx*8], rcx
    inc     qword ptr [rbp-40]
    inc     qword ptr [rbp-32]
    jmp     co_loop

ifdef TEST_IO
co_take_p:
    call    co_next_arg                 ; rax -> value or 0
    test    rax, rax
    jz      co_usage
    mov     qword ptr [rbp-48], rax
    jmp     co_loop
; "--stage <n>:<folder>" - place positional n inside <folder> in the archive.
; The value is UTF-16 and pfx_stage takes UTF-8, so it is converted here; the
; index is everything before the first ':', the folder everything after.
co_take_stage:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     qword ptr [rbp-56], rax
    ; find the ':'
    xor     r9, r9
cts_scan:
    movzx   r10d, word ptr [rax+r9*2]
    test    r10d, r10d
    jz      co_usage                    ; no colon: not a stage spec
    cmp     r10d, 3Ah
    je      cts_found
    inc     r9
    cmp     r9, 16
    jb      cts_scan
    jmp     co_usage
cts_found:
    ; terminate at the colon so wstr_to_u32 sees only the index
    mov     rax, qword ptr [rbp-56]
    mov     word ptr [rax+r9*2], 0
    mov     qword ptr [rbp-64], r9
    mov     rcx, rax
    call    wstr_to_u32
    test    edx, edx
    jz      co_badnum
    cmp     eax, MAX_ARGS
    jae     co_badnum
    mov     dword ptr [rbp-72], eax
    ; the folder is what followed the colon
    mov     rax, qword ptr [rbp-56]
    mov     r9, qword ptr [rbp-64]
    lea     rdx, [rax+r9*2+2]
    WINCALL WideCharToMultiByte, CP_UTF8, 0, rdx, -1, addr g_stagebuf, 1024, 0, 0
    test    eax, eax
    jz      co_usage
    dec     eax                         ; drop the terminator
    mov     r8d, eax
    lea     rdx, [g_stagebuf]
    movsxd  rcx, dword ptr [rbp-72]
    call    pfx_stage
    test    eax, eax
    jnz     co_usage
    jmp     co_loop
endif
co_take_o:
    call    co_next_arg                 ; rax -> wide output path or 0
    test    rax, rax
    jz      co_usage
    mov     qword ptr [g_cfg_out], rax
    jmp     co_loop
co_take_m:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     rcx, rax
    call    wstr_to_u32
    test    edx, edx
    jz      co_badnum
    ; -m is in MiB on the command line; store KiB.  Range check both ways.
    cmp     eax, 8
    jb      co_badnum
    cmp     eax, 4096
    ja      co_badnum
    shl     eax, 10                     ; MiB -> KiB (max 4096<<10, no overflow)
    mov     dword ptr [g_cfg_m], eax
    jmp     co_loop
co_take_t:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     rcx, rax
    call    wstr_to_u32
    test    edx, edx
    jz      co_badnum
    cmp     eax, ARGON2_MIN_T
    jb      co_badnum
    cmp     eax, ARGON2_MAX_T
    ja      co_badnum
    mov     dword ptr [g_cfg_t], eax
    jmp     co_loop
co_take_minlen:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     rcx, rax
    call    wstr_to_u32
    test    edx, edx
    jz      co_badnum
    cmp     eax, 1
    jb      co_badnum
    cmp     eax, MAX_PASSWORD_BYTES
    ja      co_badnum
    mov     dword ptr [g_cfg_pwminlen], eax
    jmp     co_loop
co_take_minclasses:
    call    co_next_arg
    test    rax, rax
    jz      co_usage
    mov     rcx, rax
    call    wstr_to_u32
    test    edx, edx
    jz      co_badnum
    cmp     eax, 4
    ja      co_badnum                   ; 0..4
    mov     dword ptr [g_cfg_pwminclasses], eax
    jmp     co_loop
co_take_nopolicy:
    mov     dword ptr [g_cfg_pwminlen], 1
    mov     dword ptr [g_cfg_pwminclasses], 0
    inc     qword ptr [rbp-32]          ; flag: consume just this arg
    jmp     co_loop
co_take_compress:
    mov     dword ptr [g_cfg_compress], 1
    mov     dword ptr [g_cfg_compress_set], 1
    inc     qword ptr [rbp-32]
    jmp     co_loop
co_take_store:
    mov     dword ptr [g_cfg_compress], 0
    mov     dword ptr [g_cfg_compress_set], 1
    inc     qword ptr [rbp-32]
    jmp     co_loop
co_take_json:
    mov     dword ptr [g_cfg_json], 1
    inc     qword ptr [rbp-32]          ; flag: consume just this arg
    jmp     co_loop
co_take_log:
    call    co_next_arg                 ; rax -> LEVEL value or 0
    test    rax, rax
    jz      co_usage
    mov     rcx, rax
    call    parse_loglevel
    cmp     eax, -1
    je      co_usage
    mov     dword ptr [g_cfg_loglevel], eax
    jmp     co_loop
co_take_logfile:
    call    co_next_arg                 ; rax -> wide log path or 0
    test    rax, rax
    jz      co_usage
    mov     qword ptr [g_cfg_logfile], rax
    jmp     co_loop

co_check:
    ; ---- store positional count globally (all positionals are inputs) -------
    mov     rax, qword ptr [rbp-40]
    mov     qword ptr [g_poscount], rax
    mov     r10, qword ptr [rbp-24]
    mov     eax, dword ptr [r10].CMDENT.pos_args
    cmp     eax, ENC_VAR
    je      co_var_pos
    ; ---- fixed positional count must match ----------------------------------
    cmp     qword ptr [rbp-40], rax
    jne     co_usage
    jmp     co_setin
co_var_pos:
    cmp     qword ptr [rbp-40], 1       ; encrypt: at least one input
    jb      co_usage
co_setin:
    ; g_cfg_in = first positional (if any); the output is set only by -o
    cmp     qword ptr [rbp-40], 0
    je      co_pwcheck
    lea     r11, [g_positionals]
    mov     rcx, qword ptr [r11+0]
    mov     qword ptr [g_cfg_in], rcx
co_pwcheck:
    ; ---- password: convert any provided -p; error only if it's mandatory -----
    mov     rcx, qword ptr [rbp-48]     ; -p value (0 if none was given)
    test    rcx, rcx
    jnz     co_haspw
    ; none supplied: fail only when this command requires a password
    mov     eax, dword ptr [r10].CMDENT.needs_pass
    test    eax, eax
    jnz     co_usage
    jmp     co_ok
co_haspw:
    call    password_to_utf8            ; eax = 1 ok
    test    eax, eax
    jz      co_badpass
co_ok:
    mov     eax, EXIT_OK
    jmp     co_done
co_usage:
    lea     rcx, [msg_usage]
    mov     edx, msg_usage_len
    call    print_err
    mov     eax, EXIT_USAGE
    jmp     co_done
co_badnum:
    lea     rcx, [msg_badnum]
    mov     edx, msg_badnum_len
    call    print_err
    mov     eax, EXIT_USAGE
    jmp     co_done
co_badopt:
    ; Name it.  "usage:" alone leaves the user comparing their command line
    ; against a wall of text to find the one word that is wrong.  The argument
    ; is reloaded from its index rather than kept in a register, because
    ; print_err lands in the middle.
    lea     rcx, [msg_badopt]
    mov     edx, msg_badopt_len
    call    print_err
    mov     rax, qword ptr [rbp-32]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+rax*8]
    call    print_wze
    lea     rcx, [msg_badopt2]
    mov     edx, msg_badopt2_len
    call    print_err
    mov     eax, EXIT_USAGE
    jmp     co_done
co_badpass:
    lea     rcx, [msg_badpass]
    mov     edx, msg_badpass_len
    call    print_err
    mov     eax, EXIT_USAGE
co_done:
    FRAME_EPILOG
    ret

; -- helper: advance to next arg, return its ptr in rax (0 if none) ----------
; (shares the parent frame; only touches rax/r10/r11)
co_next_arg:
    inc     qword ptr [rbp-32]          ; skip the option itself
    mov     rax, qword ptr [rbp-32]
    mov     r10d, dword ptr [g_argc]
    cmp     rax, r10
    jae     cna_none
    lea     r11, [g_argv]
    mov     rax, qword ptr [r11+rax*8]
    inc     qword ptr [rbp-32]          ; consume the value
    ret
cna_none:
    xor     eax, eax
    ret
collect_options endp

; =============================================================================
; password_to_utf8(rcx = wide password ptr) -> eax = 1 ok / 0 invalid
; Strict conversion (rejects invalid UTF-16), enforces 1..1024 bytes,
; then wipes the wide original inside g_argbuf.
; =============================================================================
password_to_utf8 proc frame
    FRAME_PROLOG 32 + 32 + 16
    ; locals: [rbp-24] = wide ptr
    mov     qword ptr [rbp-24], rcx

    ; WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, src, -1,
    ;                     g_cfg_pass, MAX+1, NULL, NULL)
    WINCALL WideCharToMultiByte, CP_UTF8, WC_ERR_INVALID_CHARS, rcx, -1, addr g_cfg_pass, MAX_PASSWORD_BYTES+1, 0, 0
    test    eax, eax
    jz      p2u_bad                     ; invalid UTF-16 or too long
    dec     eax                         ; exclude NUL
    cmp     eax, MIN_PASSWORD_BYTES
    jb      p2u_bad
    cmp     eax, MAX_PASSWORD_BYTES
    ja      p2u_bad
    mov     dword ptr [g_cfg_passlen], eax

    ; ---- wipe the wide password copy in g_argbuf ----------------------------
    mov     rcx, qword ptr [rbp-24]
    xor     edx, edx
p2u_measure:
    cmp     word ptr [rcx+rdx*2], 0
    je      p2u_wipe
    inc     edx
    cmp     edx, ARGBUF_CHARS
    jb      p2u_measure
p2u_wipe:
    shl     edx, 1                      ; chars -> bytes
    call    secure_zero                 ; rcx = ptr, rdx = bytes
    mov     eax, 1
    jmp     p2u_done
p2u_bad:
    ; wipe whatever partial conversion landed in the buffer
    lea     rcx, [g_cfg_pass]
    mov     edx, MAX_PASSWORD_BYTES+1
    call    secure_zero
    xor     eax, eax
p2u_done:
    FRAME_EPILOG
    ret
password_to_utf8 endp

; =============================================================================
; Command handlers (skeleton stubs).  Each is a DLPV landing-pad target.
; Real implementations arrive in later phases; the stubs already receive a
; fully validated configuration.
; =============================================================================
LANDING_PAD
ifndef TEST_IO
; The five password-taking verbs stay in cmd_table so that "myrkr encrypt x"
; is still RECOGNISED - drop them and is_cli_command would treat "encrypt" as a
; dropped file path and open the GUI on a file of that name, which reads as a
; bug rather than a policy.  They are recognised and refused instead.
cli_refused proc frame
    FRAME_PROLOG 32
    lea     rcx, [msg_no_cli1]
    mov     edx, msg_no_cli1_len
    call    print_err
    lea     rcx, [msg_no_cli2]
    mov     edx, msg_no_cli2_len
    call    print_err
    lea     rcx, [msg_no_cli3]
    mov     edx, msg_no_cli3_len
    call    print_err
    lea     rcx, [msg_no_cli4]
    mov     edx, msg_no_cli4_len
    call    print_err
    lea     rcx, [msg_no_cli5]
    mov     edx, msg_no_cli5_len
    call    print_err
    mov     eax, EXIT_USAGE
    FRAME_EPILOG
    ret
cli_refused endp
endif

cmd_encrypt proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_encrypt
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_encrypt endp

LANDING_PAD
cmd_decrypt proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_decrypt
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_decrypt endp

LANDING_PAD
cmd_verify proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_verify
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_verify endp

LANDING_PAD
cmd_list proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_list
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_list endp

LANDING_PAD
cmd_zipadd proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_zip_add
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_zipadd endp

ifdef TEST_IO
LANDING_PAD
cmd_estream proc frame
    FRAME_PROLOG 32
    call    do_estream
    FRAME_EPILOG
    ret
cmd_estream endp

LANDING_PAD
cmd_dataobj proc frame
    FRAME_PROLOG 32
    call    do_dataobj
    FRAME_EPILOG
    ret
cmd_dataobj endp
endif

LANDING_PAD
cmd_add proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_add
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_add endp

LANDING_PAD
cmd_delete proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_delete
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_delete endp

LANDING_PAD
cmd_unzip proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_unzip
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_unzip endp

LANDING_PAD
cmd_zip proc frame
    FRAME_PROLOG 32
ifdef TEST_IO
    call    do_zip
else
    call    cli_refused
endif
    FRAME_EPILOG
    ret
cmd_zip endp

LANDING_PAD
cmd_hash proc frame
    FRAME_PROLOG 32
    call    do_hash
    FRAME_EPILOG
    ret
cmd_hash endp

LANDING_PAD
cmd_selftest proc frame
    FRAME_PROLOG 32
    call    run_selftest
    test    eax, eax
    jz      cst_ok
    lea     rcx, [msg_st_fail]
    mov     edx, msg_st_fail_len
    call    print_a
    mov     eax, EXIT_SELFTEST
    FRAME_EPILOG
    ret
cst_ok:
    lea     rcx, [msg_st_ok]
    mov     edx, msg_st_ok_len
    call    print_a
    mov     eax, EXIT_OK
    FRAME_EPILOG
    ret
cmd_selftest endp

LANDING_PAD
cmd_bench proc frame
    FRAME_PROLOG 32
    call    do_bench
    FRAME_EPILOG
    ret
cmd_bench endp

; =============================================================================
; is_cli_command -> eax = 1 if argv[1] names a known command verb, else 0.
; Used by the hybrid entry point to choose CLI vs GUI mode.  Requires
; parse_cmdline to have already populated g_argv/g_argc.  Read-only (no output).
; =============================================================================
public is_cli_command
is_cli_command proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] = table cursor, [rbp-32] = table index
    cmp     dword ptr [g_argc], 2
    jb      icc_no
    lea     rax, [cmd_table]
    mov     qword ptr [rbp-24], rax
    mov     qword ptr [rbp-32], 0
icc_loop:
    cmp     qword ptr [rbp-32], CMD_COUNT
    jae     icc_optck
    mov     r10, qword ptr [rbp-24]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+8]      ; argv[1]
    mov     rdx, qword ptr [r10].CMDENT.name_ptr
    call    wstr_eq
    test    eax, eax
    jnz     icc_yes
    add     qword ptr [rbp-24], sizeof CMDENT
    inc     qword ptr [rbp-32]
    jmp     icc_loop
icc_optck:
    ; not a known verb - but a leading '-' means an option (e.g. --help, -h):
    ; route those to the CLI too so terminal usage prints to the console.  A
    ; file path handed by Explorer/drag-drop is drive-absolute, never '-'.
    lea     r11, [g_argv]
    mov     r10, qword ptr [r11+8]      ; argv[1] ptr
    movzx   eax, word ptr [r10]         ; first UTF-16 unit
    cmp     eax, '-'
    je      icc_yes
    xor     eax, eax
    FRAME_EPILOG
    ret
icc_yes:
    mov     eax, 1
    FRAME_EPILOG
    ret
icc_no:
    xor     eax, eax
    FRAME_EPILOG
    ret
is_cli_command endp

; =============================================================================
; dispatch - match argv[1] against cmd_table, validate options, run handler
; through a DLPV-guarded indirect call.  Returns exit code in eax.
; =============================================================================
public dispatch
dispatch proc frame
    FRAME_PROLOG 48
    ; locals: [rbp-24] = table cursor, [rbp-32] = table index

    cmp     dword ptr [g_argc], 2
    jb      dp_usage

    lea     rax, [cmd_table]
    mov     qword ptr [rbp-24], rax
    mov     qword ptr [rbp-32], 0
dp_loop:
    cmp     qword ptr [rbp-32], CMD_COUNT
    jae     dp_usage
    mov     r10, qword ptr [rbp-24]
    lea     r11, [g_argv]
    mov     rcx, qword ptr [r11+8]      ; argv[1] = command word
    mov     rdx, qword ptr [r10].CMDENT.name_ptr
    call    wstr_eq
    test    eax, eax
    jnz     dp_found
    add     qword ptr [rbp-24], sizeof CMDENT
    inc     qword ptr [rbp-32]
    jmp     dp_loop

dp_found:
ifndef TEST_IO
    ; Refuse BEFORE the options are parsed.  Parsing first would reject these
    ; verbs for the wrong reason - "-p is required" (or "unknown option -p")
    ; - printing usage instead of saying why the command is gone.
    cmp     qword ptr [rbp-32], CMD_NOCLI
    jae     @F
    call    cli_refused
    jmp     dp_done
@@:
endif
    mov     rcx, qword ptr [rbp-24]     ; CMDENT*
    call    collect_options
    cmp     eax, EXIT_OK
    jne     dp_done                     ; validation failed; eax = exit code
    ; HKLM policy is loaded before the options are parsed, so a flag written here
    ; would otherwise sit on top of it - re-assert the enforced values before the
    ; handler sees them (gui.asm:apply_policy_locks).
    call    apply_policy_locks
    mov     r10, qword ptr [rbp-24]
    mov     rax, qword ptr [r10].CMDENT.handler
    CALL_GUARDED rax                    ; DLPV-checked indirect call
    ; ---- audit log: command name + outcome -> Event Log --------------------
    mov     dword ptr [rbp-32], eax     ; stash exit code (index local is done)
    mov     r10, qword ptr [rbp-24]
    mov     rcx, qword ptr [r10].CMDENT.name_ptr
    mov     edx, dword ptr [rbp-32]
    call    log_result
    mov     eax, dword ptr [rbp-32]     ; restore exit code
    jmp     dp_done

dp_usage:
    lea     rcx, [msg_usage]
    mov     edx, msg_usage_len
    call    print_err
    mov     eax, EXIT_USAGE
dp_done:
    FRAME_EPILOG
    ret
dispatch endp

; =============================================================================
; start - process entry point
; =============================================================================
public start
start proc frame
    sub     rsp, 56                     ; 32 shadow + 2 locals + align
    .allocstack 56
    .endprolog
    ; locals: [rsp+32] = cpu-ok flag, [rsp+40] = exit code

    DBG     'A'
    call    cpu_gate                    ; 1. feature detect (raw frame)
    mov     dword ptr [rsp+32], eax
    DBG     'B'
    call    hardening_init              ; 2. canary + shadow stack live
    test    eax, eax
    jz      st_oom_raw
    DBG     'C'
    call    con_init                    ; 3. console up (protected calls ok now)
    DBG     'D'
    cmp     dword ptr [rsp+32], 0
    je      st_nocpu
    call    iat_lockdown                ; 4. imports now read-only
    DBG     'E'
    call    parse_cmdline               ; 5. tokenize + dispatch
    DBG     'F'
    call    dispatch
    mov     dword ptr [rsp+40], eax
    DBG     'G'

st_exit:
    ; Wipe every registered secret region (password + derived key) and unlock
    ; it, in that order.  Supersedes the old g_cfg_pass-only wipe: g_key was
    ; left for the process teardown to deal with.
    call    secmem_wipe_all
    WINCALL ExitProcess, dword ptr [rsp+40]     ; never returns

st_nocpu:
    lea     rcx, [msg_nocpu]
    mov     edx, msg_nocpu_len
    call    print_err
    mov     dword ptr [rsp+40], EXIT_NOCPU
    jmp     st_exit
st_oom_raw:
    ; hardened runtime unavailable: exit without touching protected helpers
    WINCALL ExitProcess, EXIT_OOM
start endp

end
