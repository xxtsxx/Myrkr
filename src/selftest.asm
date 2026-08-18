; =============================================================================
; selftest.asm - embedded known-answer tests for every primitive
; -----------------------------------------------------------------------------
; run_selftest() -> eax = 0 if all pass, else count of failures.
; Each primitive is validated against an official test vector (RFC / NIST).
; As primitives are added (blake2b, argon2id, aes-gcm) their checks append
; here so a single `myrkr selftest` covers the whole crypto core.
; =============================================================================

include macros.inc

extern sha256_hash:proc
extern ct_memcmp:proc
extern print_a:proc
extern gcm_seal:proc
extern gcm_open:proc
extern blake2b_hash:proc
extern argon2_compress:proc
extern argon2id_hash:proc
extern check_password_policy:proc
extern sanitize_name:proc
extern idx_rev_bump:proc
extern nonce_set:proc
extern prog_speed_x10:proc
extern prog_eta_s:proc
extern GetTickCount64:proc
externdef g_prog_total:qword
externdef g_prog_done:qword
externdef g_prog_startms:qword
extern vsplit_bytes:proc
externdef g_idxrev:dword
externdef g_cfg_splitidx:dword
extern secmem_locked:proc               ; secmem.asm: 1 = all secret regions pinned
extern crc32_update:proc
extern sha1_hash:proc
extern pbkdf2_hmac_sha1:proc
extern inflate:proc
extern aes_expand_key:proc
extern aes_ecb_block:proc
extern deflate_buf:proc
extern rlog_begin:proc                  ; ramlog.asm: the in-RAM action log
extern rlog_append:proc
extern rlog_added:proc
extern rlog_extracted:proc
extern rlog_finish:proc
extern rlog_flatten:proc
extern rlog_wipe:proc
extern mem_free:proc
extern rows_reset:proc
extern rows_add:proc
extern rows_sort_tree:proc
extern row_path:proc
externdef g_rowcount:qword
externdef g_cfg_pass:byte
externdef g_cfg_passlen:dword
externdef g_cfg_pwminlen:dword
externdef g_cfg_pwminclasses:dword

ARGON2REQ struct
    t_cost      dd ?
    m_cost      dd ?
    lanes       dd ?
    outlen      dd ?
    version     dd ?
    atype       dd ?
    pwd         dq ?
    pwdlen      dd ?
    saltlen     dd ?
    salt        dq ?
    secret      dq ?
    secretlen   dd ?
    adlen       dd ?
    ad          dq ?
    outp        dq ?
ARGON2REQ ends

GCMREQ struct
    key     dq ?
    iv      dq ?
    aad     dq ?
    aadlen  dq ?
    inp     dq ?
    inlen   dq ?
    outp    dq ?
    tag     dq ?
GCMREQ ends

.const
st_abc          db "abc"
; SHA-256("abc")
sha_abc_exp     db 0bah,078h,016h,0bfh,08fh,001h,0cfh,0eah,041h,041h,040h,0deh,05dh,0aeh,022h,023h
                db 0b0h,003h,061h,0a3h,096h,017h,07ah,09ch,0b4h,010h,0ffh,061h,0f2h,000h,015h,0adh

CSTR st_pass_sha,  "  [PASS] sha-256  (FIPS 180-4 'abc')",13,10
CSTR st_fail_sha,  "  [FAIL] sha-256",13,10
CSTR st_pass_gcm,  "  [PASS] aes-256-gcm  (NIST SP800-38D + round-trip)",13,10
CSTR st_fail_gcm,  "  [FAIL] aes-256-gcm",13,10
CSTR st_pass_aad,  "  [PASS] aes-256-gcm + AAD round-trip",13,10
CSTR st_fail_aad,  "  [FAIL] aes-256-gcm + AAD",13,10
CSTR st_pass_ip,   "  [PASS] aes-256-gcm in-place + tail",13,10
CSTR st_fail_ip,   "  [FAIL] aes-256-gcm in-place + tail",13,10
CSTR st_pass_b2b,  "  [PASS] blake2b  (RFC 7693 'abc')",13,10
CSTR st_fail_b2b,  "  [FAIL] blake2b",13,10
CSTR st_pass_ac,   "  [PASS] argon2 compress  (block KAT)",13,10
CSTR st_fail_ac,   "  [FAIL] argon2 compress",13,10
CSTR st_pass_a2,   "  [PASS] argon2id  (RFC 9106 test vector)",13,10
CSTR st_fail_a2,   "  [FAIL] argon2id",13,10
CSTR st_pass_pw,   "  [PASS] password policy (length + class rules)",13,10
CSTR st_fail_pw,   "  [FAIL] password policy",13,10
CSTR st_pass_san,  "  [PASS] archive path-traversal safety",13,10
CSTR st_fail_san,  "  [FAIL] archive path-traversal safety",13,10
CSTR st_pass_rev,  "  [PASS] index revision  (stops at the ceiling, no nonce wrap)",13,10
CSTR st_fail_rev,  "  [FAIL] index revision  (stops at the ceiling, no nonce wrap)",13,10
CSTR st_pass_non,  "  [PASS] gcm nonce layout  (counter and segment cannot overlap)",13,10
CSTR st_fail_non,  "  [FAIL] gcm nonce layout  (counter and segment cannot overlap)",13,10
CSTR st_pass_rate, "  [PASS] progress rate/eta  (128-bit product, cap, and the gates)",13,10
CSTR st_fail_rate, "  [FAIL] progress rate/eta  (128-bit product, cap, and the gates)",13,10
CSTR st_pass_spl,  "  [PASS] split presets  (Off is 0, sizes strictly increasing)",13,10
CSTR st_fail_spl,  "  [FAIL] split presets  (Off is 0, sizes strictly increasing)",13,10
CSTR st_pass_lock, "  [PASS] secret buffers locked (non-pageable)",13,10
CSTR st_fail_lock, "  [FAIL] secret buffers NOT locked - password/key may page to disk",13,10
san_safe1   db "tree/a.txt",0
san_safe2   db "a/b/c.txt",0
san_bad1    db "../evil",0
san_bad2    db "a/b/../../../etc",0
san_bad3    db "/abs/path",0
san_bad4    db "C:\windows\x",0
san_bad5    db "..\win",0
; DOS device names.  There were no vectors for these at all, so the CON/COM3
; rule that has shipped for many versions was never checked either.
san_bad6    db "CON",0                  ; the 3-char table
san_bad7    db "com3.txt",0             ; base before the dot, 4-char table
san_bad8    db "CONIN$",0               ; 6 - too long for either fixed table
san_bad9    db "dir/conout$.txt",0      ; 7, and not the first component
; The other half, and the half that matters more: names that merely LOOK like
; devices must still extract.  A sanitiser that over-rejects silently loses
; files, and nothing else here would notice.
san_safe3   db "conin",0                ; 5 - one short of CONIN$
san_safe4   db "coninx",0               ; 6 - right length, wrong name
san_safe5   db "conout",0               ; 6 - CONOUT is not a device; CONOUT$ is
san_safe6   db "readme",0               ; 6 - ordinary
san_safe7   db "conin$x",0              ; 7 - right length, wrong name
; policy test passwords
pw_short    db "Abc12"                       ; 5 chars (too short)
pw_short_n  equ $ - pw_short
pw_oneclass db "abcdefghijklmnopqrs"         ; 19 lower only (too few classes)
pw_oneclass_n equ $ - pw_oneclass
pw_good3    db "Abcdefghij12"                ; 12 chars, U+L+D = 3 classes
pw_good3_n  equ $ - pw_good3

; ---- nonce layout vectors ---------------------------------------------------
; Each row is: counter (8), segment (4), then the 12 bytes nonce_set must write.
;
; Chosen so that ANY overlap between the two fields shows up.  The counter
; values have their top bits set and the segments have their low bits set, so a
; segment written even one bit low - or a counter allowed even one bit high -
; changes a byte the vector pins.  Row 2 is the index's own nonce base, row 5 is
; the pair that would collide if the segment were OR-ed into the counter rather
; than placed above it.
align 8
non_vec:
    dq  0                    ; counter
    dd  0                    ; segment
    db  0,0,0,0,0,0,0,0, 0,0,0,0
    dq  1
    dd  0
    db  1,0,0,0,0,0,0,0, 0,0,0,0
    dq  8000000000000000h    ; IDX_NONCE_BASE
    dd  0
    db  0,0,0,0,0,0,0,80h, 0,0,0,0
    dq  0
    dd  1
    db  0,0,0,0,0,0,0,0, 1,0,0,0
    dq  0FFFFFFFFFFFFFFFFh   ; every counter bit set...
    dd  0FFFFFFFFh           ; ...and every segment bit set
    db  0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh,0FFh, 0FFh,0FFh,0FFh,0FFh
    dq  0FFFFFFFFh           ; a counter that fills the low 32 bits
    dd  0                    ; and segment 0 - must NOT look like the next row
    db  0FFh,0FFh,0FFh,0FFh,0,0,0,0, 0,0,0,0
    dq  0
    dd  0FFFFFFFFh           ; segment 0xFFFFFFFF, counter 0
    db  0,0,0,0,0,0,0,0, 0FFh,0FFh,0FFh,0FFh
NON_VEC_STRIDE  equ 24
NON_VEC_COUNT   equ 7
align 8
arg_cksum   dq 05ee3a5c79eba0a63h
arg_out0    dq 0dc71308d33513477h
; RFC 9106 Argon2id tag (t=3,m=32,p=4,secret,ad)
a2_exp      db 00dh,064h,00dh,0f5h,08dh,078h,076h,06ch,008h,0c0h,037h,0a3h,04ah,08bh,053h,0c9h
            db 0d0h,01eh,0f0h,045h,02dh,075h,0b6h,05eh,0b5h,025h,020h,0e9h,06bh,001h,0e6h,059h

; BLAKE2b-512("abc") - RFC 7693 Appendix A
b2b_abc_exp db 0bah,080h,0a5h,03fh,098h,01ch,04dh,00dh,06ah,027h,097h,0b6h,09fh,012h,0f6h,0e9h
            db 04ch,021h,02fh,014h,068h,05ah,0c4h,0b7h,04bh,012h,0bbh,06fh,0dbh,0ffh,0a2h,0d1h
            db 07dh,087h,0c5h,039h,02ah,0abh,079h,02dh,0c2h,052h,0d5h,0deh,045h,033h,0cch,095h
            db 018h,0d3h,08ah,0a8h,0dbh,0f1h,092h,05ah,0b9h,023h,086h,0edh,0d4h,000h,099h,023h
CSTR st_pass_crc,  "  [PASS] crc-32  ('123456789' = 0xCBF43926)",13,10
CSTR st_fail_crc,  "  [FAIL] crc-32",13,10
CSTR st_pass_sha1, "  [PASS] sha-1  (FIPS 180-4 'abc')",13,10
CSTR st_fail_sha1, "  [FAIL] sha-1",13,10
CSTR st_pass_pbk,  "  [PASS] pbkdf2-hmac-sha1  (WinZip-AES 1000 iters)",13,10
CSTR st_fail_pbk,  "  [FAIL] pbkdf2-hmac-sha1",13,10
CSTR st_pass_inf,  "  [PASS] inflate  (raw DEFLATE round-trip)",13,10
CSTR st_fail_inf,  "  [FAIL] inflate",13,10
CSTR st_pass_aes,  "  [PASS] aes-128/192/256 ECB  (FIPS-197 vectors)",13,10
CSTR st_fail_aes,  "  [FAIL] aes-128/192/256 ECB",13,10
CSTR st_pass_def,  "  [PASS] deflate  (encode -> inflate round-trip)",13,10
CSTR st_fail_def,  "  [FAIL] deflate",13,10
CSTR st_pass_tree, "  [PASS] container tree order  (a folder keeps its contents)",13,10
CSTR st_fail_tree, "  [FAIL] container tree order",13,10
CSTR st_pass_rlog, "  [PASS] action log  (spans chunk boundaries intact)",13,10
CSTR st_fail_rlog, "  [FAIL] action log",13,10
; FIPS-197 key 000102..1f, plaintext 00112233..ff and the three ciphertexts
aeskat_key  db 000h,001h,002h,003h,004h,005h,006h,007h,008h,009h,00ah,00bh,00ch,00dh,00eh,00fh
            db 010h,011h,012h,013h,014h,015h,016h,017h,018h,019h,01ah,01bh,01ch,01dh,01eh,01fh
aeskat_pt   db 000h,011h,022h,033h,044h,055h,066h,077h,088h,099h,0aah,0bbh,0cch,0ddh,0eeh,0ffh
aeskat_c128 db 069h,0c4h,0e0h,0d8h,06ah,07bh,004h,030h,0d8h,0cdh,0b7h,080h,070h,0b4h,0c5h,05ah
aeskat_c192 db 0ddh,0a9h,07ch,0a4h,086h,04ch,0dfh,0e0h,06eh,0afh,070h,0a0h,0ech,00dh,071h,091h
aeskat_c256 db 08eh,0a2h,0b7h,0cah,051h,067h,045h,0bfh,0eah,0fch,049h,090h,04bh,049h,060h,089h
; ---- container tree ordering -------------------------------------------------
; Rows as an APPEND leaves them: the inventory is in write order, so a file
; added to a folder arrives at the end whatever it is called.  tro_in is that
; order, tro_want is what the list has to show.
;
; Two of these pairs are ordered wrongly by an ordinary text comparison, and
; both are the reason row_tree_cmp folds before it compares:
;
;   "in\sub\added.txt" vs "in\sub2.txt" - '\' is 5Ch and '2' is 32h, so as text
;       sub2.txt sorts BETWEEN sub and its children: a sibling drawn in the
;       middle of another folder's contents, at the wrong indent.
;   "in\Zeta.txt" vs "in\alpha.txt" - 'Z' is 5Ah and 'a' is 61h, so as text
;       every capitalised name jumps above every lowercase one.
;
; Backslashes, not '/': rows_from_index has already translated them.
tro_p0      dw 'i','n',0
tro_p1      dw 'i','n','\','s','u','b',0
tro_p2      dw 'i','n','\','s','u','b','\','c','.','t','x','t',0
tro_p3      dw 'i','n','\','s','u','b','2','.','t','x','t',0
tro_p4      dw 'i','n','\','Z','e','t','a','.','t','x','t',0
tro_p5      dw 'i','n','\','a','l','p','h','a','.','t','x','t',0
tro_p6      dw 'i','n','\','s','u','b','\','a','d','d','e','d','.','t','x','t',0
align 8
tro_in      dq tro_p0, tro_p1, tro_p2, tro_p3, tro_p4, tro_p5, tro_p6
tro_fl      dq 1, 1, 0, 0, 0, 0, 0          ; ROWF_DIR for "in" and "in\sub"
; Folders first among siblings, then files, each folded-alphabetical:
;   in                     the root
;     sub                  the only folder under it, so it leads
;       added.txt          appended last, drawn where it belongs
;       c.txt
;     alpha.txt            then the files, with case folded out of the way
;     sub2.txt
;     Zeta.txt
tro_want    dq tro_p0, tro_p1, tro_p6, tro_p2, tro_p5, tro_p3, tro_p4
TRO_N       equ 7

; ---- action log --------------------------------------------------------------
; The one part of ramlog.asm that can be wrong without anything noticing is the
; chunk split: an append that spans two chunks loses or repeats a byte in the
; seam, and the result is a log that reads fine until you look closely at one
; line in the middle of a big job.  So the vector is deliberately larger than a
; chunk, and every byte of it is checked - not the ends, which is where a seam
; bug is precisely NOT visible.
;
; RL_CHUNK is mirrored from ramlog.asm ON PURPOSE.  constcheck fails the build
; when two modules disagree about a constant, so raising the chunk size there
; cannot quietly leave this test appending less than one chunk and still passing.
;
; The FIRST piece of the vector is not appended - it is PRINTED, and the check
; expects to find it in the log anyway.  That is the tee in console.asm, which
; is the whole reason the window can show a refusal reason at all, and it is
; otherwise reachable only by running the GUI and looking.  A tee that stops
; firing would leave an empty viewer and break nothing else.
RL_CHUNK    equ 65536
RL_FILL_N   equ 1024
RL_REPS     equ (RL_CHUNK / RL_FILL_N) + 16      ; comfortably over two chunks
RL_MARK_N   equ 16
RL_FILL_TOTAL equ RL_FILL_N * RL_REPS
RL_TOTAL    equ rl_tee_len + RL_FILL_TOTAL + RL_MARK_N
CSTR rl_tee, "  [tee ] one line via print_a, which the log has to have seen",13,10
rl_tail     db "--MYRKR-LOG-TAIL"
; a non-repeating byte for every offset in the block, so a seam that duplicates
; or drops one shifts everything after it into a mismatch
rl_fill label byte
rl_x = 0
    rept RL_FILL_N
        db (rl_x * 7 + 13) and 0FFh
rl_x = rl_x + 1
    endm
; ---- the per-entry lines -----------------------------------------------------
; rlog_added / rlog_extracted are what pack.asm, zip.asm and unzip.asm call once
; per entry, and they are the difference between a log that says "zipped 913
; file(s)" and one that says which.  Both the tag and the exact layout are pinned
; here, because the only other place either is visible is a window.
;
; The two names are deliberately different SHAPES: the first is passed with
; length 0 and has to be measured to its NUL, the second carries an explicit
; length and no terminator at all.  Both forms are used by the real call sites -
; two of the four have a length in hand and two have a C string - so a change
; that broke either would break half the log.
; TWO added and ONE extracted, and not one of each.  One of each was written
; first and a mutation that swapped the two counters in the summary passed
; against it: the vector was symmetric, so the swap was invisible.  The counts
; have to differ for the check to be able to tell them apart.
rl_n1       db "alpha.txt",0
rl_n3       db "delta.dat"
RL_N3_LEN   equ 9
rl_n2       db "beta/gamma.bin"
RL_N2_LEN   equ 14
rl_want2    db "  added     alpha.txt",13,10,"  added     delta.dat",13,10
            db "  extracted beta/gamma.bin",13,10
RL_WANT2_N  equ $ - rl_want2
; ---- the closing summary -----------------------------------------------------
; The timestamp cannot be a fixed vector, so it is checked by SHAPE: every 'd'
; in the mask must be a digit and every other character must match exactly.  That
; catches the failures that matter - a field of the wrong width, a separator in
; the wrong place, a component that never got written - without pinning the test
; to the second it ran.
;
; The counts are the point of the rest: 1 added and 1 extracted are the two lines
; above, so the summary is checked against the log it is summarising.
rl_fhead    db 13,10,"  finished "
RL_FHEAD_N  equ $ - rl_fhead
rl_smask    db "dddd-dd-dd dd:dd:dd"
RL_STAMP_N  equ $ - rl_smask
rl_want3    db 13,10,"  2 added, 1 extracted",13,10,"  completed successfully",13,10
RL_WANT3_N  equ $ - rl_want3
RL_FIN_N    equ RL_WANT2_N + RL_FHEAD_N + RL_STAMP_N + RL_WANT3_N

crc_msg     db "123456789"
crc_msg_n   equ $ - crc_msg
sha1_abc    db "abc"
sha1_abc_exp db 0a9h,099h,03eh,036h,047h,006h,081h,06ah,0bah,03eh,025h,071h,078h,050h,0c2h,06ch,09ch,0d0h,0d8h,09dh
pbk_exp:
            db 0efh,0d0h,0b0h,036h,023h,00bh,0c8h,074h,08bh,0f2h,017h,0feh,033h,025h,073h,025h
            db 08ah,02dh,0a7h,0f3h,05eh,0cdh,09ah,0ech,025h,0a8h,000h,08ch,01fh,0e9h,056h,0a8h
            db 034h,09eh,012h,097h,028h,0d6h,0aah,0a5h,052h,047h,03ah,07fh,046h,0b2h,0ech,06fh
            db 083h,04fh,0ceh,06ah,0dah,0c7h,023h,070h,058h,06bh,078h,0f0h,04dh,092h,08ch,0cfh
            db 02eh,0c7h
pbk_pw      db "Sw0rdf1sh!Passphrase"
pbk_pw_n    equ $ - pbk_pw
pbk_salt    db 013h,0ebh,0a8h,042h,0d4h,068h,00eh,017h,047h,06ah,03eh,016h,090h,053h,0eah,082h
; raw DEFLATE with a DYNAMIC Huffman block (BTYPE=2) - exercises HLIT/HDIST/
; HCLEN parsing and the code-length repeat codes (regression for the HDIST bug)
inf_src:
            db 085h,092h,051h,00eh,084h,020h,00ch,044h,0afh,0e2h,0d5h,04ah,096h,0a8h,059h,054h
            db 092h,0e5h,06bh,04fh,0bfh,0a6h,04fh,074h,040h,093h,0fdh,0a0h,029h,065h,066h,098h
            db 052h,0cah,014h,08bh,00dh,0f3h,0b6h,087h,0e2h,069h,0b9h,00ah,06fh,0cbh,0d9h,086h
            db 057h,04ch,07bh,03eh,0dah,0b2h,034h,038h,00eh,029h,087h,08bh,018h,0f3h,067h,04eh
            db 0dbh,0aah,007h,04eh,0b2h,094h,0a7h,04ah,08ah,08fh,022h,0e4h,0e0h,09ch,0e2h,064h
            db 0f6h,044h,09ch,010h,015h,08dh,0d6h,0b7h,097h,005h,0e8h,052h,0a4h,0d5h,01bh,020h
            db 0b8h,00fh,0d6h,04fh,0cfh,041h,0abh,02eh,02fh,092h,0b5h,02eh,032h,05ch,00bh,0abh
            db 0a7h,0c7h,07fh,00dh,069h,02bh,0bah,042h,0dfh,050h,063h,0e8h,06eh,011h,09dh,0f3h
            db 08ch,0b7h,085h,079h,0bbh,05fh,027h,02eh,003h,006h,02dh,01fh,041h,0bfh,040h,0dbh
            db 0ddh,0b1h,0b4h,085h,0eah,0e6h,098h,075h,0f3h,04ch,0bdh,010h,018h,079h,037h,060h
            db 06ah,0bah,099h,0cdh,00fh
inf_exp:
            db 074h,068h,065h,074h,061h,020h,069h,06fh,074h,061h,020h,074h,068h,065h,074h,061h
            db 020h,074h,068h,065h,074h,061h,020h,069h,06fh,074h,061h,020h,06bh,061h,070h,070h
            db 061h,020h,064h,065h,06ch,074h,061h,020h,067h,061h,06dh,06dh,061h,020h,069h,06fh
            db 074h,061h,020h,074h,068h,065h,074h,061h,020h,06bh,061h,070h,070h,061h,020h,067h
            db 061h,06dh,06dh,061h,020h,062h,065h,074h,061h,020h,074h,068h,065h,074h,061h,020h
            db 065h,070h,073h,069h,06ch,06fh,06eh,020h,067h,061h,06dh,06dh,061h,020h,062h,065h
            db 074h,061h,020h,069h,06fh,074h,061h,020h,061h,06ch,070h,068h,061h,020h,06bh,061h
            db 070h,070h,061h,020h,065h,074h,061h,020h,074h,068h,065h,074h,061h,020h,06bh,061h
            db 070h,070h,061h,020h,067h,061h,06dh,06dh,061h,020h,06bh,061h,070h,070h,061h,020h
            db 061h,06ch,070h,068h,061h,020h,069h,06fh,074h,061h,020h,062h,065h,074h,061h,020h
            db 061h,06ch,070h,068h,061h,020h,061h,06ch,070h,068h,061h,020h,064h,065h,06ch,074h
            db 061h,020h,064h,065h,06ch,074h,061h,020h,06bh,061h,070h,070h,061h,020h,061h,06ch
            db 070h,068h,061h,020h,074h,068h,065h,074h,061h,020h,07ah,065h,074h,061h,020h,074h
            db 068h,065h,074h,061h,020h,06bh,061h,070h,070h,061h,020h,064h,065h,06ch,074h,061h
            db 020h,069h,06fh,074h,061h,020h,064h,065h,06ch,074h,061h,020h,065h,070h,073h,069h
            db 06ch,06fh,06eh,020h,074h,068h,065h,074h,061h,020h,061h,06ch,070h,068h,061h,020h
            db 062h,065h,074h,061h,020h,074h,068h,065h,074h,061h,020h,065h,070h,073h,069h,06ch
            db 06fh,06eh,020h,065h,074h,061h,020h,069h,06fh,074h,061h,020h,062h,065h,074h,061h
            db 020h,065h,070h,073h,069h,06ch,06fh,06eh,020h,07ah,065h,074h,061h,020h,064h,065h
            db 06ch,074h,061h,020h,069h,06fh,074h,061h,020h,065h,070h,073h,069h,06ch,06fh,06eh
            db 020h,061h,06ch,070h,068h,061h,020h,062h,065h,074h,061h,020h,06bh,061h,070h,070h
            db 061h,020h,062h,065h,074h,061h,020h,065h,074h,061h,020h,062h,065h,074h,061h,020h
            db 065h,070h,073h,069h,06ch,06fh,06eh,020h,065h,074h,061h,020h,062h,065h,074h,061h
            db 020h,061h,06ch,070h,068h,061h,020h,061h,06ch,070h,068h,061h,020h,064h,065h,06ch
            db 074h,061h,020h,064h,065h,06ch,074h,061h,020h,061h,06ch,070h,068h,061h,020h,074h
            db 068h,065h,074h,061h,020h,065h,074h,061h,020h,065h,074h,061h,020h,065h,074h,061h
            db 020h,062h,065h,074h,061h,020h,06bh,061h,070h,070h,061h,020h,064h,065h,06ch,074h
            db 061h,020h,065h,070h,073h,069h,06ch,06fh,06eh,020h,07ah,065h,074h,061h,020h,062h
            db 065h,074h,061h,020h,065h,070h,073h,069h,06ch,06fh,06eh,020h,07ah,065h,074h,061h
            db 020h,061h,06ch,070h,068h,061h,020h,065h,074h,061h,020h,062h,065h,074h,061h,020h
            db 067h,061h,06dh,06dh,061h,020h,064h,065h,06ch,074h,061h,020h,062h,065h,074h,061h
            db 020h,061h,06ch,070h,068h,061h,020h,061h,06ch,070h,068h,061h,020h,074h,068h,065h
            db 074h,061h,020h,074h,068h,065h,074h,061h,020h,067h,061h,06dh,06dh,061h,020h,069h
            db 06fh,074h,061h,020h,064h,065h,06ch,074h,061h,020h,074h,068h,065h,074h,061h,020h
            db 069h,06fh,074h,061h,020h,064h,065h,06ch,074h,061h,020h,067h,061h,06dh,06dh,061h
            db 020h,065h,074h,061h,020h,065h,074h,061h,020h,062h,065h,074h,061h,020h,065h,074h
            db 061h,020h,065h,074h,061h,020h,064h,065h,06ch,074h,061h,020h,061h,06ch,070h,068h
            db 061h,020h,065h,070h,073h,069h,06ch,06fh,06eh,020h,06bh,061h,070h,070h,061h,020h
            db 065h,070h,073h,069h,06ch,06fh,06eh,020h,061h,06ch,070h,068h,061h,020h,064h,065h
            db 06ch,074h,061h,020h,067h,061h,06dh,06dh,061h,020h,065h,074h,061h,020h,06bh,061h
            db 070h,070h,061h,020h,06bh,061h,070h,070h,061h,020h,062h,065h,074h,061h,020h,061h
            db 06ch,070h,068h,061h,020h,067h,061h,06dh,06dh,061h,020h,064h,065h,06ch,074h,061h
            db 020h,074h,068h,065h,074h,061h,020h,065h,070h,073h,069h,06ch,06fh,06eh

CSTR st_hdr,       "running self-tests:",13,10

; NIST SP800-38D AES-256-GCM: key=0(32), iv=0(12), aad=none, pt=16 zero bytes
gcm_ct_exp  db 0ceh,0a7h,040h,03dh,04dh,060h,06bh,06eh,007h,04eh,0c5h,0d3h,0bah,0f3h,09dh,018h
gcm_tag_exp db 0d0h,0d1h,0c8h,0a7h,099h,099h,06bh,0f0h,026h,05bh,098h,0b5h,0d4h,08ah,0b9h,019h

.data?
st_out          db 32 dup (?)
align 8
g_st_nonce      db 12 dup (?)        ; one nonce, for the layout vectors
g_st_nonces     db (64*12) dup (?)   ; 8 counters x 8 segments, for the
                                     ; all-pairs distinctness sweep
align 8
b2b_out         db 64 dup (?)
gcm_aadbuf      db 32 dup (?)
gcm_pt2b        db 16 dup (?)
gcm_dec2        db 16 dup (?)
gcm_tag2b       db 16 dup (?)
align 16
gcm_ip_pt       db 20 dup (?)        ; 20 bytes -> 1 block + 4-byte tail
gcm_ip_buf      db 20 dup (?)        ; in-place work buffer
gcm_ip_tag      db 16 dup (?)
align 16
arg_x           db 1024 dup (?)
arg_y           db 1024 dup (?)
arg_o           db 1024 dup (?)
a2_pwd          db 32 dup (?)
a2_salt         db 16 dup (?)
a2_secret       db 8 dup (?)
a2_ad           db 12 dup (?)
a2_out          db 32 dup (?)
align 8
a2_req          ARGON2REQ <>
gcm_key         db 32 dup (?)
gcm_iv          db 12 dup (?)
gcm_pt          db 16 dup (?)
gcm_ct          db 16 dup (?)
gcm_tag         db 16 dup (?)
gcm_dec         db 16 dup (?)
align 8
greq            GCMREQ <>
sha1_out        db 20 dup (?)
pbk_out         db 66 dup (?)
inf_out         db 800 dup (?)
inf_outlen      dq ?
aeskat_rk       db 240 dup (?)
aeskat_blk      db 16 dup (?)
def_out         db 2048 dup (?)
def_outlen      dq ?

.code

; LOADPW src,len - copy a test password into g_cfg_pass, set g_cfg_passlen
LOADPW macro src, len
    lea     r12, [src]
    lea     r13, [g_cfg_pass]
    xor     r9d, r9d
@@:
    mov     al, byte ptr [r12+r9]
    mov     byte ptr [r13+r9], al
    inc     r9d
    cmp     r9d, len
    jb      @B
    mov     dword ptr [g_cfg_passlen], len
endm

; AESKAT klen, expc - expand aeskat_key (klen bytes), ECB-encrypt aeskat_pt,
; compare to expc; jump to st_aes_fail on mismatch.
AESKAT macro klen, expc
    local cp
    lea     r10, [aeskat_pt]
    lea     r11, [aeskat_blk]
    xor     r9d, r9d
cp:
    mov     al, byte ptr [r10+r9]
    mov     byte ptr [r11+r9], al
    inc     r9d
    cmp     r9d, 16
    jb      cp
    lea     rcx, [aeskat_key]
    mov     rdx, klen
    lea     r8, [aeskat_rk]
    call    aes_expand_key
    lea     rcx, [aeskat_rk]
    lea     rdx, [aeskat_blk]
    mov     r8, rax                          ; Nr
    call    aes_ecb_block
    lea     rcx, [aeskat_blk]
    lea     rdx, [expc]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_aes_fail
endm

; =============================================================================
; run_selftest -> eax = number of failures
; =============================================================================
public run_selftest
run_selftest proc frame
    FRAME_PROLOG 96
    ; [rbp-24] = failure count
    mov     qword ptr [rbp-24], 0

    lea     rcx, [st_hdr]
    mov     edx, st_hdr_len
    call    print_a

    ; ---- SHA-256("abc") -----------------------------------------------------
    lea     rcx, [st_abc]
    mov     rdx, 3
    lea     r8, [st_out]
    call    sha256_hash
    lea     rcx, [st_out]
    lea     rdx, [sha_abc_exp]
    mov     r8, 32
    call    ct_memcmp
    test    eax, eax
    jnz     st_sha_fail
    lea     rcx, [st_pass_sha]
    mov     edx, st_pass_sha_len
    call    print_a
    jmp     st_after_sha
st_sha_fail:
    lea     rcx, [st_fail_sha]
    mov     edx, st_fail_sha_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_sha:

    ; ---- AES-256-GCM seal (key/iv/pt all zero via BSS) ----------------------
    ; fill request: seal pt -> ct, tag
    lea     rax, [gcm_key]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [gcm_iv]
    mov     qword ptr [greq].GCMREQ.iv, rax
    mov     qword ptr [greq].GCMREQ.aad, 0
    mov     qword ptr [greq].GCMREQ.aadlen, 0
    lea     rax, [gcm_pt]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 16
    lea     rax, [gcm_ct]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [gcm_tag]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal

    ; compare ciphertext
    lea     rcx, [gcm_ct]
    lea     rdx, [gcm_ct_exp]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_gcm_fail
    ; compare tag
    lea     rcx, [gcm_tag]
    lea     rdx, [gcm_tag_exp]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_gcm_fail

    ; ---- round-trip: open ct -> dec, must validate and match pt -------------
    lea     rax, [gcm_ct]
    mov     qword ptr [greq].GCMREQ.inp, rax
    lea     rax, [gcm_dec]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rcx, [greq]
    call    gcm_open
    test    eax, eax                    ; 0 = tag valid
    jnz     st_gcm_fail
    lea     rcx, [gcm_dec]
    lea     rdx, [gcm_pt]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_gcm_fail

    lea     rcx, [st_pass_gcm]
    mov     edx, st_pass_gcm_len
    call    print_a
    jmp     st_after_gcm
st_gcm_fail:
    lea     rcx, [st_fail_gcm]
    mov     edx, st_fail_gcm_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_gcm:

    ; ---- AES-256-GCM with AAD: seal then open round-trip --------------------
    lea     rax, [gcm_key]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [gcm_iv]
    mov     qword ptr [greq].GCMREQ.iv, rax
    lea     rax, [gcm_aadbuf]
    mov     qword ptr [greq].GCMREQ.aad, rax
    mov     qword ptr [greq].GCMREQ.aadlen, 32
    lea     rax, [gcm_pt2b]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 16
    lea     rax, [gcm_ct]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [gcm_tag2b]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    ; open it back
    lea     rax, [gcm_ct]
    mov     qword ptr [greq].GCMREQ.inp, rax
    lea     rax, [gcm_dec2]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rcx, [greq]
    call    gcm_open
    test    eax, eax
    jnz     st_aad_fail
    lea     rcx, [gcm_dec2]
    lea     rdx, [gcm_pt2b]
    mov     r8, 16
    call    ct_memcmp
    test    eax, eax
    jnz     st_aad_fail
    lea     rcx, [st_pass_aad]
    mov     edx, st_pass_aad_len
    call    print_a
    jmp     st_after_aad
st_aad_fail:
    lea     rcx, [st_fail_aad]
    mov     edx, st_fail_aad_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_aad:

    ; ---- AES-256-GCM in-place decrypt with a partial-block tail -------------
    ; seal 20 bytes (pt) -> ip_buf (ct); then open ip_buf IN PLACE; result must
    ; equal pt and authenticate.  Guards the in-place tail GHASH ordering.
    lea     rax, [gcm_key]
    mov     qword ptr [greq].GCMREQ.key, rax
    lea     rax, [gcm_iv]
    mov     qword ptr [greq].GCMREQ.iv, rax
    lea     rax, [gcm_aadbuf]
    mov     qword ptr [greq].GCMREQ.aad, rax
    mov     qword ptr [greq].GCMREQ.aadlen, 32
    lea     rax, [gcm_ip_pt]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.inlen, 20
    lea     rax, [gcm_ip_buf]
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rax, [gcm_ip_tag]
    mov     qword ptr [greq].GCMREQ.tag, rax
    lea     rcx, [greq]
    call    gcm_seal
    ; open in place: inp == outp == ip_buf
    lea     rax, [gcm_ip_buf]
    mov     qword ptr [greq].GCMREQ.inp, rax
    mov     qword ptr [greq].GCMREQ.outp, rax
    lea     rcx, [greq]
    call    gcm_open
    test    eax, eax
    jnz     st_ip_fail
    lea     rcx, [gcm_ip_buf]
    lea     rdx, [gcm_ip_pt]
    mov     r8, 20
    call    ct_memcmp
    test    eax, eax
    jnz     st_ip_fail
    lea     rcx, [st_pass_ip]
    mov     edx, st_pass_ip_len
    call    print_a
    jmp     st_after_ip
st_ip_fail:
    lea     rcx, [st_fail_ip]
    mov     edx, st_fail_ip_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_ip:

    ; ---- BLAKE2b-512("abc") -------------------------------------------------
    lea     rcx, [st_abc]
    mov     rdx, 3
    lea     r8, [b2b_out]
    mov     r9, 64
    call    blake2b_hash
    lea     rcx, [b2b_out]
    lea     rdx, [b2b_abc_exp]
    mov     r8, 64
    call    ct_memcmp
    test    eax, eax
    jnz     st_b2b_fail
    lea     rcx, [st_pass_b2b]
    mov     edx, st_pass_b2b_len
    call    print_a
    jmp     st_after_b2b
st_b2b_fail:
    lea     rcx, [st_fail_b2b]
    mov     edx, st_fail_b2b_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_b2b:

    ; ---- Argon2 block compression (known-answer test) -----------------------
    ; X[i] = 0x0101010101010101*(i+1) ; Y[i] = 0x0202020202020202*(i+1)
    lea     r12, [arg_x]
    lea     r13, [arg_y]
    xor     r9d, r9d
st_acfill:
    lea     r8, [r9+1]
    mov     rax, 00101010101010101h
    imul    rax, r8
    mov     qword ptr [r12 + r9*8], rax
    mov     rax, 00202020202020202h
    imul    rax, r8
    mov     qword ptr [r13 + r9*8], rax
    inc     r9d
    cmp     r9d, 128
    jb      st_acfill

    lea     rcx, [arg_o]
    lea     rdx, [arg_x]
    lea     r8,  [arg_y]
    xor     r9d, r9d                    ; with_xor = 0
    call    argon2_compress

    ; xor-checksum of the 128 output qwords
    lea     r12, [arg_o]
    xor     rax, rax
    xor     r9d, r9d
st_acsum:
    xor     rax, qword ptr [r12 + r9*8]
    inc     r9d
    cmp     r9d, 128
    jb      st_acsum
    mov     r10, qword ptr [arg_cksum]
    cmp     rax, r10
    jne     st_ac_fail
    mov     rax, qword ptr [arg_o]
    mov     r10, qword ptr [arg_out0]
    cmp     rax, r10
    jne     st_ac_fail
    lea     rcx, [st_pass_ac]
    mov     edx, st_pass_ac_len
    call    print_a
    jmp     st_after_ac
st_ac_fail:
    lea     rcx, [st_fail_ac]
    mov     edx, st_fail_ac_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_ac:

    ; ---- Argon2id full KDF (RFC 9106 vector) --------------------------------
    ; fill inputs: pwd=0x01*32, salt=0x02*16, secret=0x03*8, ad=0x04*12
    lea     r12, [a2_pwd]
    mov     ecx, 32
st_fpwd:
    mov     byte ptr [r12], 1
    inc     r12
    dec     ecx
    jnz     st_fpwd
    lea     r12, [a2_salt]
    mov     ecx, 16
st_fsalt:
    mov     byte ptr [r12], 2
    inc     r12
    dec     ecx
    jnz     st_fsalt
    lea     r12, [a2_secret]
    mov     ecx, 8
st_fsec:
    mov     byte ptr [r12], 3
    inc     r12
    dec     ecx
    jnz     st_fsec
    lea     r12, [a2_ad]
    mov     ecx, 12
st_fad:
    mov     byte ptr [r12], 4
    inc     r12
    dec     ecx
    jnz     st_fad

    ; fill request
    lea     r12, [a2_req]
    mov     dword ptr [r12].ARGON2REQ.t_cost, 3
    mov     dword ptr [r12].ARGON2REQ.m_cost, 32
    mov     dword ptr [r12].ARGON2REQ.lanes, 4
    mov     dword ptr [r12].ARGON2REQ.outlen, 32
    mov     dword ptr [r12].ARGON2REQ.version, 13h
    mov     dword ptr [r12].ARGON2REQ.atype, 2
    lea     rax, [a2_pwd]
    mov     qword ptr [r12].ARGON2REQ.pwd, rax
    mov     dword ptr [r12].ARGON2REQ.pwdlen, 32
    lea     rax, [a2_salt]
    mov     qword ptr [r12].ARGON2REQ.salt, rax
    mov     dword ptr [r12].ARGON2REQ.saltlen, 16
    lea     rax, [a2_secret]
    mov     qword ptr [r12].ARGON2REQ.secret, rax
    mov     dword ptr [r12].ARGON2REQ.secretlen, 8
    lea     rax, [a2_ad]
    mov     qword ptr [r12].ARGON2REQ.ad, rax
    mov     dword ptr [r12].ARGON2REQ.adlen, 12
    lea     rax, [a2_out]
    mov     qword ptr [r12].ARGON2REQ.outp, rax

    lea     rcx, [a2_req]
    call    argon2id_hash
    test    eax, eax
    jnz     st_a2_fail
    lea     rcx, [a2_out]
    lea     rdx, [a2_exp]
    mov     r8, 32
    call    ct_memcmp
    test    eax, eax
    jnz     st_a2_fail
    lea     rcx, [st_pass_a2]
    mov     edx, st_pass_a2_len
    call    print_a
    jmp     st_after_a2
st_a2_fail:
    lea     rcx, [st_fail_a2]
    mov     edx, st_fail_a2_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_a2:

    ; ---- password policy (default min 12 chars / 3 of 4 classes) ------------
    mov     dword ptr [g_cfg_pwminlen], 12
    mov     dword ptr [g_cfg_pwminclasses], 3
    LOADPW  pw_short, pw_short_n            ; 5 chars -> too short (1)
    call    check_password_policy
    cmp     eax, 1
    jne     st_pw_fail
    LOADPW  pw_oneclass, pw_oneclass_n      ; 19 lower-only -> too few (2)
    call    check_password_policy
    cmp     eax, 2
    jne     st_pw_fail
    LOADPW  pw_good3, pw_good3_n            ; 12 chars, 3 classes -> ok (0)
    call    check_password_policy
    test    eax, eax
    jnz     st_pw_fail
    lea     rcx, [st_pass_pw]
    mov     edx, st_pass_pw_len
    call    print_a
    jmp     st_after_pw
st_pw_fail:
    lea     rcx, [st_fail_pw]
    mov     edx, st_fail_pw_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_pw:

    ; ---- archive entry-name path-traversal safety --------------------------
    lea     rcx, [san_safe1]
    call    sanitize_name
    test    eax, eax
    jnz     st_san_fail
    lea     rcx, [san_safe2]
    call    sanitize_name
    test    eax, eax
    jnz     st_san_fail
    lea     rcx, [san_bad1]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_bad2]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_bad3]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_bad4]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_bad5]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_bad6]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_bad7]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_bad8]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_bad9]
    call    sanitize_name
    test    eax, eax
    jz      st_san_fail
    lea     rcx, [san_safe3]
    call    sanitize_name
    test    eax, eax
    jnz     st_san_fail
    lea     rcx, [san_safe4]
    call    sanitize_name
    test    eax, eax
    jnz     st_san_fail
    lea     rcx, [san_safe5]
    call    sanitize_name
    test    eax, eax
    jnz     st_san_fail
    lea     rcx, [san_safe6]
    call    sanitize_name
    test    eax, eax
    jnz     st_san_fail
    lea     rcx, [san_safe7]
    call    sanitize_name
    test    eax, eax
    jnz     st_san_fail
    lea     rcx, [st_pass_san]
    mov     edx, st_pass_san_len
    call    print_a
    jmp     st_after_san
st_san_fail:
    lea     rcx, [st_fail_san]
    mov     edx, st_fail_san_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_san:

    ; ---- the index revision cannot wrap ------------------------------------
    ; The index's nonce is IDX_NONCE_BASE + revision, and the revision is a
    ; 32-bit field: wrapping it reissues revision 0's nonce under the same key
    ; over different plaintext.  No test can reach that by counting to 2^32, so
    ; g_idxrev is driven straight to the ceiling here.
    ;
    ; Both directions, because a guard that refuses everything would also "pass"
    ; a one-sided test - and it would refuse every edit of every container.
    mov     dword ptr [g_idxrev], IDX_REV_MAX - 1
    call    idx_rev_bump
    test    eax, eax
    jnz     st_rev_fail                     ; must still advance one below it
    cmp     dword ptr [g_idxrev], IDX_REV_MAX
    jne     st_rev_fail
    call    idx_rev_bump
    test    eax, eax
    jz      st_rev_fail                     ; must refuse AT the ceiling
    cmp     dword ptr [g_idxrev], IDX_REV_MAX
    jne     st_rev_fail                     ; and must not have moved it
    mov     dword ptr [g_idxrev], 0         ; a fresh container starts here
    call    idx_rev_bump
    test    eax, eax
    jnz     st_rev_fail
    cmp     dword ptr [g_idxrev], 1
    jne     st_rev_fail
    mov     dword ptr [g_idxrev], 0         ; leave nothing behind
    lea     rcx, [st_pass_rev]
    mov     edx, st_pass_rev_len
    call    print_a
    jmp     st_after_rev
st_rev_fail:
    mov     dword ptr [g_idxrev], 0
    lea     rcx, [st_fail_rev]
    mov     edx, st_fail_rev_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_rev:

    ; ---- the GCM nonce's two fields cannot overlap -------------------------
    ; The nonce is 96 bits: a 64-bit counter and, above it, a 32-bit segment.
    ; The top 32 were written as zero until phase B spent them, so segment 0
    ; still reproduces every nonce this tool has ever written.
    ;
    ; Nonce reuse under one key is the one mistake in this design that no later
    ; fix undoes, so the layout is pinned by vectors rather than left to be
    ; obvious - and the vectors are chosen so that a segment written even one
    ; bit too low, or a counter allowed even one bit too high, changes a byte
    ; one of them names.  The last two rows are the pair that would become
    ; EQUAL if the segment were OR-ed into the counter instead of placed above
    ; it, which is the shape the mistake would actually take.
    xor     r9d, r9d                        ; vector index
st_non_loop:
    cmp     r9d, NON_VEC_COUNT
    jae     st_non_uniq
    mov     r10, r9
    imul    r10, r10, NON_VEC_STRIDE
    lea     r11, [non_vec]
    add     r11, r10
    mov     qword ptr [rbp-32], r9          ; the loop index, across the call
    mov     rcx, qword ptr [r11]            ; counter
    lea     rdx, [g_st_nonce]
    mov     r8d, dword ptr [r11+8]          ; segment
    call    nonce_set
    mov     r9, qword ptr [rbp-32]
    mov     r10, r9
    imul    r10, r10, NON_VEC_STRIDE
    lea     r11, [non_vec]
    add     r11, r10
    add     r11, 12                         ; -> the expected 12 bytes
    lea     rcx, [g_st_nonce]
    mov     rdx, r11
    mov     r8, 12
    call    ct_memcmp
    test    eax, eax
    jnz     st_non_fail
    mov     r9, qword ptr [rbp-32]   ; ct_memcmp clobbered it; the loop index
                                     ; lives in the frame, not in a volatile
    inc     r9d
    jmp     st_non_loop
st_non_uniq:
    ; And the property those vectors exist to protect: distinct (counter,
    ; segment) pairs must give distinct nonces.  Built here rather than reasoned
    ; about, because "obviously injective" is exactly what a later edit breaks.
    ; 8 counters x 8 segments = 64 nonces, every pair compared.
    xor     r9d, r9d                        ; pair index
st_non_build:
    cmp     r9d, 64
    jae     st_non_cmp
    mov     eax, r9d
    shr     eax, 3                          ; counter index 0..7
    mov     ecx, eax
    mov     rax, 1
    shl     rax, cl
    dec     rax                             ; 0,1,3,7,15,... - varied bit patterns
    mov     rcx, rax
    mov     eax, r9d
    and     eax, 7                          ; segment index 0..7
    mov     r8d, 1
    mov     r10d, eax
    push    rcx
    mov     ecx, r10d
    shl     r8d, cl
    dec     r8d
    pop     rcx
    mov     rdx, r9
    imul    rdx, rdx, 12
    lea     r11, [g_st_nonces]
    add     rdx, r11
    mov     qword ptr [rbp-32], r9
    call    nonce_set
    mov     r9, qword ptr [rbp-32]
    inc     r9d
    jmp     st_non_build
st_non_cmp:
    xor     r9d, r9d
st_non_i:
    cmp     r9d, 64
    jae     st_non_ok
    lea     r10d, [r9d+1]
st_non_j:
    cmp     r10d, 64
    jae     st_non_inext
    mov     qword ptr [rbp-32], r9
    mov     qword ptr [rbp-40], r10
    mov     rcx, r9
    imul    rcx, rcx, 12
    lea     r11, [g_st_nonces]
    add     rcx, r11
    mov     rdx, r10
    imul    rdx, rdx, 12
    add     rdx, r11
    mov     r8, 12
    call    ct_memcmp
    test    eax, eax
    jz      st_non_fail                     ; two pairs produced one nonce
    mov     r9, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-40]
    inc     r10d
    jmp     st_non_j
st_non_inext:
    inc     r9d
    jmp     st_non_i
st_non_ok:
    lea     rcx, [st_pass_non]
    mov     edx, st_pass_non_len
    call    print_a
    jmp     st_after_non
st_non_fail:
    lea     rcx, [st_fail_non]
    mov     edx, st_fail_non_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_non:

    ; ---- progress rate and eta ---------------------------------------------
    ; The eta multiply (remaining * elapsed_ms) genuinely needs 128 bits at the
    ; sizes this tool now handles - 100 TB remaining over an hour is past 2^64 -
    ; and MUL/DIV give it for free, PROVIDED the quotient-overflow guard fires
    ; first when even the answer will not fit.  Driven here with injected state
    ; because no test can wait an hour; ranges not equalities, because the clock
    ; ticks a few ms between the set and the call.
    ;
    ; V1: 100 MB in exactly ~1s of 200 MB -> ~100.0 MB/s x10, eta ~1s.
    WINCALL GetTickCount64
    sub     rax, 1000
    mov     qword ptr [g_prog_startms], rax
    mov     qword ptr [g_prog_total], 200000000
    mov     qword ptr [g_prog_done], 100000000
    call    prog_speed_x10
    cmp     rax, 950
    jb      st_rate_fail
    cmp     rax, 1050
    ja      st_rate_fail
    call    prog_eta_s
    cmp     rax, 2
    ja      st_rate_fail                    ; 0..2 tolerates the tick
    ; V2: the 128-bit path AND the cap.  100 TiB remaining after 1 GiB in an
    ; hour: remaining*elapsed ~= 4e20 > 2^64, true eta ~= 4e6 s > the cap.
    WINCALL GetTickCount64
    mov     rcx, 3600000
    sub     rax, rcx
    mov     qword ptr [g_prog_startms], rax
    mov     rax, 100
    shl     rax, 40                          ; 100 TiB remaining...
    mov     rcx, 1
    shl     rcx, 30                          ; ...after 1 GiB done
    mov     qword ptr [g_prog_done], rcx
    add     rax, rcx
    mov     qword ptr [g_prog_total], rax
    call    prog_eta_s
    cmp     rax, 359999
    jne     st_rate_fail
    ; V3: the gates.  No first byte yet -> speed 0, eta -1.
    mov     qword ptr [g_prog_startms], 0
    call    prog_speed_x10
    test    rax, rax
    jnz     st_rate_fail
    call    prog_eta_s
    cmp     rax, -1
    jne     st_rate_fail
    ; V4: done == total -> eta 0 regardless of the clock.
    WINCALL GetTickCount64
    sub     rax, 5000
    mov     qword ptr [g_prog_startms], rax
    mov     rax, qword ptr [g_prog_total]
    mov     qword ptr [g_prog_done], rax
    call    prog_eta_s
    test    rax, rax
    jnz     st_rate_fail
    ; leave nothing behind for a real operation to inherit
    mov     qword ptr [g_prog_total], 0
    mov     qword ptr [g_prog_done], 0
    mov     qword ptr [g_prog_startms], 0
    lea     rcx, [st_pass_rate]
    mov     edx, st_pass_rate_len
    call    print_a
    jmp     st_after_rate
st_rate_fail:
    mov     qword ptr [g_prog_total], 0
    mov     qword ptr [g_prog_done], 0
    mov     qword ptr [g_prog_startms], 0
    lea     rcx, [st_fail_rate]
    mov     edx, st_fail_rate_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_rate:

    ; ---- the split presets -------------------------------------------------
    ; The slider shows a NAME and the writer uses a SIZE, from two tables sharing
    ; one index.  Nothing checks by eye that entry 2 says "700 MB (CD)" and means
    ; 700,000,000 - and a slider that says one and does the other is wrong in a
    ; way nobody notices until the disc will not take the file.
    ;
    ; What is checkable mechanically: index 0 is Off and must be 0, because 0 is
    ; what the whole write path treats as "do not split"; and the rest must
    ; strictly increase, which is what breaks if a row is inserted, duplicated or
    ; reordered in one table and not the other.
    mov     dword ptr [g_cfg_splitidx], 0
    call    vsplit_bytes
    test    rax, rax
    jnz     st_spl_fail                     ; Off must mean 0
    xor     r9d, r9d
    xor     r10, r10                        ; previous size
st_spl_next:
    inc     r9d
    cmp     r9d, SPLIT_MAX_IDX
    ja      st_spl_ok
    mov     dword ptr [g_cfg_splitidx], r9d
    mov     qword ptr [rbp-32], r9
    mov     qword ptr [rbp-40], r10
    call    vsplit_bytes
    mov     r9, qword ptr [rbp-32]
    mov     r10, qword ptr [rbp-40]
    cmp     rax, r10
    jbe     st_spl_fail                     ; not strictly increasing
    mov     r10, rax
    jmp     st_spl_next
st_spl_ok:
    mov     dword ptr [g_cfg_splitidx], 0
    lea     rcx, [st_pass_spl]
    mov     edx, st_pass_spl_len
    call    print_a
    jmp     st_after_spl
st_spl_fail:
    mov     dword ptr [g_cfg_splitidx], 0
    lea     rcx, [st_fail_spl]
    mov     edx, st_fail_spl_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_spl:

    ; ---- secret buffers pinned (non-pageable) ------------------------------
    ; Not a KAT: a report on a property of THIS process.  A failure means the
    ; password and key may reach the pagefile, which is a real weakening, so it
    ; is surfaced rather than silently tolerated - but see secmem.asm for why a
    ; failed lock does not abort the operation.
    call    secmem_locked
    test    eax, eax
    jz      st_lock_fail
    lea     rcx, [st_pass_lock]
    mov     edx, st_pass_lock_len
    call    print_a
    jmp     st_after_lock
st_lock_fail:
    lea     rcx, [st_fail_lock]
    mov     edx, st_fail_lock_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_lock:

    ; ---- CRC-32 ("123456789" -> 0xCBF43926) --------------------------------
    xor     ecx, ecx
    lea     rdx, [crc_msg]
    mov     r8, crc_msg_n
    call    crc32_update
    cmp     eax, 0CBF43926h
    je      st_crc_ok
    lea     rcx, [st_fail_crc]
    mov     edx, st_fail_crc_len
    call    print_a
    inc     qword ptr [rbp-24]
    jmp     st_after_crc
st_crc_ok:
    lea     rcx, [st_pass_crc]
    mov     edx, st_pass_crc_len
    call    print_a
st_after_crc:

    ; ---- SHA-1("abc") -------------------------------------------------------
    lea     rcx, [sha1_abc]
    mov     rdx, 3
    lea     r8, [sha1_out]
    call    sha1_hash
    lea     rcx, [sha1_out]
    lea     rdx, [sha1_abc_exp]
    mov     r8, 20
    call    ct_memcmp
    test    eax, eax
    jnz     st_sha1_fail
    lea     rcx, [st_pass_sha1]
    mov     edx, st_pass_sha1_len
    call    print_a
    jmp     st_after_sha1
st_sha1_fail:
    lea     rcx, [st_fail_sha1]
    mov     edx, st_fail_sha1_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_sha1:

    ; ---- PBKDF2-HMAC-SHA1 (WinZip-AES key derivation, 1000 iters) -----------
    mov     qword ptr [rsp+32], 1000          ; iters  (arg5)
    lea     rax, [pbk_out]
    mov     qword ptr [rsp+40], rax           ; out    (arg6)
    mov     qword ptr [rsp+48], 66            ; dklen  (arg7)
    lea     rcx, [pbk_pw]
    mov     rdx, pbk_pw_n
    lea     r8, [pbk_salt]
    mov     r9, 16
    call    pbkdf2_hmac_sha1
    lea     rcx, [pbk_out]
    lea     rdx, [pbk_exp]
    mov     r8, 66
    call    ct_memcmp
    test    eax, eax
    jnz     st_pbk_fail
    lea     rcx, [st_pass_pbk]
    mov     edx, st_pass_pbk_len
    call    print_a
    jmp     st_after_pbk
st_pbk_fail:
    lea     rcx, [st_fail_pbk]
    mov     edx, st_fail_pbk_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_pbk:

    ; ---- inflate (raw DEFLATE round-trip) -----------------------------------
    lea     rax, [inf_outlen]
    mov     qword ptr [rsp+32], rax
    lea     rcx, [inf_src]
    mov     rdx, 165
    lea     r8, [inf_out]
    mov     r9, 800
    call    inflate
    test    eax, eax
    jnz     st_inf_fail
    cmp     qword ptr [inf_outlen], 686
    jne     st_inf_fail
    lea     rcx, [inf_out]
    lea     rdx, [inf_exp]
    mov     r8, 686
    call    ct_memcmp
    test    eax, eax
    jnz     st_inf_fail
    lea     rcx, [st_pass_inf]
    mov     edx, st_pass_inf_len
    call    print_a
    jmp     st_after_inf
st_inf_fail:
    lea     rcx, [st_fail_inf]
    mov     edx, st_fail_inf_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_inf:

    ; ---- AES-128/192/256 ECB (FIPS-197 single-block vectors) ----------------
    AESKAT  16, aeskat_c128
    AESKAT  24, aeskat_c192
    AESKAT  32, aeskat_c256
    lea     rcx, [st_pass_aes]
    mov     edx, st_pass_aes_len
    call    print_a
    jmp     st_after_aes
st_aes_fail:
    lea     rcx, [st_fail_aes]
    mov     edx, st_fail_aes_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_aes:

    ; ---- DEFLATE encode -> our inflate round-trip (using inf_exp as data) ----
    lea     rcx, [inf_exp]
    mov     rdx, 686
    lea     r8, [def_out]
    mov     r9, 2048
    call    deflate_buf
    cmp     rax, -1
    je      st_def_fail
    ; inflate def_out -> inf_out, expect the original 686 bytes
    lea     r10, [def_outlen]
    mov     qword ptr [rsp+32], r10
    lea     rcx, [def_out]
    mov     rdx, rax
    lea     r8, [inf_out]
    mov     r9, 800
    call    inflate
    test    eax, eax
    jnz     st_def_fail
    cmp     qword ptr [def_outlen], 686
    jne     st_def_fail
    lea     rcx, [inf_out]
    lea     rdx, [inf_exp]
    mov     r8, 686
    call    ct_memcmp
    test    eax, eax
    jnz     st_def_fail
    lea     rcx, [st_pass_def]
    mov     edx, st_pass_def_len
    call    print_a
    jmp     st_after_def
st_def_fail:
    lea     rcx, [st_fail_def]
    mov     edx, st_fail_def_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_def:

    ; ---- container tree ordering --------------------------------------------
    ; The visible-row model is GUI state, but this is a pure function of the
    ; names and nothing here needs a window: fill it, sort it, read it back.
    ; It runs in the shipping binary on every install, which is the point - the
    ; defect it guards against (a folder's contents drawn somewhere other than
    ; under the folder) is invisible to every other test, because nothing else
    ; can see what the list looks like.
    call    rows_reset
    xor     r9, r9
st_tro_fill:
    cmp     r9, TRO_N
    jae     st_tro_filled
    mov     qword ptr [rbp-32], r9
    lea     r10, [tro_in]
    mov     rcx, qword ptr [r10+r9*8]
    lea     r11, [tro_fl]
    mov     r11, qword ptr [r11+r9*8]
    xor     edx, edx                        ; depth is not what is under test
    xor     r8, r8
    mov     r9d, r11d                       ; ROWF_DIR: folders sort first
    call    rows_add
    test    eax, eax
    jz      st_tro_fail
    mov     r9, qword ptr [rbp-32]
    inc     r9
    jmp     st_tro_fill
st_tro_filled:
    cmp     qword ptr [g_rowcount], TRO_N
    jne     st_tro_fail
    call    rows_sort_tree
    xor     r9, r9
st_tro_chk:
    cmp     r9, TRO_N
    jae     st_tro_ok
    mov     qword ptr [rbp-32], r9
    mov     rcx, r9
    call    row_path
    mov     r9, qword ptr [rbp-32]
    lea     r10, [tro_want]
    mov     r11, qword ptr [r10+r9*8]
    xor     r8, r8
st_tro_cmp:
    mov     dx, word ptr [rax+r8*2]
    cmp     dx, word ptr [r11+r8*2]
    jne     st_tro_fail
    test    dx, dx
    jz      st_tro_next
    inc     r8
    jmp     st_tro_cmp
st_tro_next:
    mov     r9, qword ptr [rbp-32]
    inc     r9
    jmp     st_tro_chk
st_tro_ok:
    call    rows_reset                      ; leave no rows behind us
    lea     rcx, [st_pass_tree]
    mov     edx, st_pass_tree_len
    call    print_a
    jmp     st_after_tree
st_tro_fail:
    call    rows_reset
    lea     rcx, [st_fail_tree]
    mov     edx, st_fail_tree_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_tree:

    ; ---- action log ---------------------------------------------------------
    ; Nothing may print between the tee line below and the flatten: print_a goes
    ; into this very buffer, so a stray message would land in the middle of the
    ; vector and the byte check would (correctly) fail on it.
    ; [rbp-40] = flattened ptr, [rbp-48] = its length
    call    rlog_begin
    lea     rcx, [rl_tee]                   ; PRINTED, not appended - the tee
    mov     edx, rl_tee_len
    call    print_a
    xor     r9, r9
st_rl_fill:
    cmp     r9, RL_REPS
    jae     st_rl_filled
    mov     qword ptr [rbp-32], r9
    lea     rcx, [rl_fill]
    mov     edx, RL_FILL_N
    call    rlog_append
    mov     r9, qword ptr [rbp-32]
    inc     r9
    jmp     st_rl_fill
st_rl_filled:
    lea     rcx, [rl_tail]
    mov     edx, RL_MARK_N
    call    rlog_append
    lea     rcx, [rbp-40]
    lea     rdx, [rbp-48]
    call    rlog_flatten
    test    eax, eax
    jz      st_rl_fail                      ; 0 = nothing came back at all
    cmp     eax, 1
    jne     st_rl_freefail                  ; 2 = it ran out of memory
    mov     rax, qword ptr [rbp-48]
    cmp     rax, RL_TOTAL
    jne     st_rl_freefail
    mov     r10, qword ptr [rbp-40]
    xor     r9, r9
st_rl_chk:
    cmp     r9, RL_TOTAL
    jae     st_rl_free
    ; expected byte at r9: the teed line, then the repeated fill, then tail
    lea     r11, [rl_tee]
    mov     r8, r9
    cmp     r9, rl_tee_len
    jb      st_rl_at
    lea     r11, [rl_tail]
    mov     r8, r9
    sub     r8, rl_tee_len + RL_FILL_TOTAL
    cmp     r9, rl_tee_len + RL_FILL_TOTAL
    jae     st_rl_at
    lea     r11, [rl_fill]
    mov     r8, r9
    sub     r8, rl_tee_len
    and     r8, RL_FILL_N - 1
st_rl_at:
    mov     al, byte ptr [r10+r9]
    cmp     al, byte ptr [r11+r8]
    jne     st_rl_freefail
    inc     r9
    jmp     st_rl_chk
st_rl_free:
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
    call    rlog_wipe
    ; a wiped log must read as empty, not as a stale copy of the last one
    lea     rcx, [rbp-40]
    lea     rdx, [rbp-48]
    call    rlog_flatten
    test    eax, eax
    jnz     st_rl_fail
    ; ---- and the per-entry lines the writers emit --------------------------
    ; Nothing may print between here and the flatten, same as above.
    call    rlog_begin
    lea     rcx, [rl_n1]
    xor     edx, edx                        ; 0 = NUL-terminated, measure it
    call    rlog_added
    lea     rcx, [rl_n3]
    mov     edx, RL_N3_LEN                  ; explicit length, no terminator
    call    rlog_added
    lea     rcx, [rl_n2]
    mov     edx, RL_N2_LEN
    call    rlog_extracted
    xor     ecx, ecx                        ; exit code 0
    xor     edx, edx                        ; not cancelled
    call    rlog_finish
    lea     rcx, [rbp-40]
    lea     rdx, [rbp-48]
    call    rlog_flatten
    cmp     eax, 1
    jne     st_rl_fail
    mov     rax, qword ptr [rbp-48]
    cmp     rax, RL_FIN_N
    jne     st_rl_freefail
    mov     r10, qword ptr [rbp-40]         ; the log
    xor     r9, r9                          ; byte index
st_rl_c2:
    cmp     r9, RL_FIN_N
    jae     st_rl_d2
    ; which of the four regions is this byte in?
    lea     r11, [rl_want2]
    mov     r8, r9
    cmp     r9, RL_WANT2_N
    jb      st_rl_exact
    lea     r11, [rl_fhead]
    mov     r8, r9
    sub     r8, RL_WANT2_N
    cmp     r9, RL_WANT2_N + RL_FHEAD_N
    jb      st_rl_exact
    lea     r11, [rl_want3]
    mov     r8, r9
    sub     r8, RL_WANT2_N + RL_FHEAD_N + RL_STAMP_N
    cmp     r9, RL_WANT2_N + RL_FHEAD_N + RL_STAMP_N
    jae     st_rl_exact
    ; the timestamp: 'd' in the mask means "any digit", anything else is literal
    lea     r11, [rl_smask]
    mov     r8, r9
    sub     r8, RL_WANT2_N + RL_FHEAD_N
    mov     al, byte ptr [r11+r8]
    cmp     al, 'd'
    jne     st_rl_exact
    mov     al, byte ptr [r10+r9]
    cmp     al, '0'
    jb      st_rl_freefail
    cmp     al, '9'
    ja      st_rl_freefail
    inc     r9
    jmp     st_rl_c2
st_rl_exact:
    mov     al, byte ptr [r10+r9]
    cmp     al, byte ptr [r11+r8]
    jne     st_rl_freefail
    inc     r9
    jmp     st_rl_c2
st_rl_d2:
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
    call    rlog_wipe
    lea     rcx, [st_pass_rlog]
    mov     edx, st_pass_rlog_len
    call    print_a
    jmp     st_after_rlog
st_rl_freefail:
    mov     rcx, qword ptr [rbp-40]
    mov     rdx, qword ptr [rbp-48]
    call    mem_free
st_rl_fail:
    call    rlog_wipe                       ; before printing: the tee is armed
    lea     rcx, [st_fail_rlog]
    mov     edx, st_fail_rlog_len
    call    print_a
    inc     qword ptr [rbp-24]
st_after_rlog:

    mov     rax, qword ptr [rbp-24]
    FRAME_EPILOG
    ret
run_selftest endp

end
