@echo off
rem ===========================================================================
rem build.cmd - assemble and link the single hybrid myrkr.exe.
rem
rem ONE executable now serves both roles: it is linked /subsystem:windows with
rem the GUI entry point (wstart), but wstart runs the full CLI when argv[1] is a
rem known command verb (encrypt/decrypt/verify/zip/unzip/hash/selftest/bench).
rem Otherwise it opens the windowed front-end.  See src\gui.asm:wstart.
rem
rem Run from a "x64 Native Tools Command Prompt for VS" (ml64/link on PATH).
rem ===========================================================================
setlocal
cd /d "%~dp0"

if not exist obj mkdir obj
if not exist bin mkdir bin

rem ---------------------------------------------------------------------------
rem Mitigations: CET hardware shadow stack plus the always-on software set
rem (DLPV, software shadow stack, stack canaries, ASLR/DEP/NX).
rem
rem NOTE: /guard:cf (Control Flow Guard) is intentionally NOT used.  CFG needs
rem per-function metadata that hand-written MASM cannot emit, and a GUI image
rem hands the OS callback pointers (window proc, thread proc) that CFG-
rem instrumented OS code validates against this image's (absent) CFG table,
rem which fast-fails at load.  Since this one binary also runs the GUI, CFG must
rem stay off; CET and the software mitigations remain.
rem
rem Optional args (combinable):
rem   build nohw     link WITHOUT /CETCOMPAT (software mitigations only)
rem   build dbg      add startup breadcrumb trace + per-primitive debug dumps,
rem                  the `redteam` fault-injection self-test, and FF-code-in-exit
rem                  (0xFADE<code>) for the security test harness (tests/redteam.py).
rem                  Implies testio (dbg is the full test build).
rem   build testio   accept a password on the command line (-p).  A RELEASE build
rem                  does NOT: the five password-taking verbs are refused there and
rem                  the secret is typed on the secure desktop instead, so that an
rem                  authorized-but-abused Myrkr cannot be driven across an estate
rem                  by a script.  The automated suite needs a non-interactive
rem                  password, so tests\run.ps1 builds a testio binary, runs
rem                  against it, and rebuilds release afterwards.
rem                  Such a build carries the MYRKR_TEST_IO_BUILD marker string and
rem                  tools\make_msi.ps1 REFUSES to package it.
rem   build strict   fail the build on ANY static-checker finding (see below)
rem   build release  reproducible build: byte-identical for a given commit
rem ---------------------------------------------------------------------------
set GUARDFLAGS=/CETCOMPAT
set ASMEXTRA=
set STRICT=0
set REPRO=0
:argloop
if "%1"=="" goto :doneargs
if /i "%1"=="nohw" set GUARDFLAGS=
if /i "%1"=="dbg" set ASMEXTRA=%ASMEXTRA% /DDBG_TRACE /DTEST_IO
if /i "%1"=="testio" set ASMEXTRA=%ASMEXTRA% /DTEST_IO
if /i "%1"=="strict" set STRICT=1
if /i "%1"=="release" set REPRO=1
shift
goto :argloop
:doneargs

rem ---------------------------------------------------------------------------
rem Reproducible release build ("build release"): two clean builds of the same
rem commit must produce a byte-identical exe (auditability - a user can rebuild
rem and match a published SHA-256).  The nondeterminism sources in a plain link
rem are (a) the PE header TimeDateStamp and (b) the absolute PDB path plus its
rem content GUID embedded in the debug directory.
rem   /Brepro                - replace every timestamp with a deterministic
rem                            content hash (PE header + debug dir + PDB sig)
rem   /pdbaltpath:myrkr.pdb  - embed just the bare PDB name, never the machine's
rem                            absolute build path, so the exe is location-independent
rem The security mitigations (CET, DEP, ASLR, highentropyva) are orthogonal link
rem flags and stay on in release builds.
rem ---------------------------------------------------------------------------
set REPROFLAGS=
set REPROFLAGS_DLL=
if "%REPRO%"=="1" set REPROFLAGS=/Brepro /pdbaltpath:myrkr.pdb
if "%REPRO%"=="1" set REPROFLAGS_DLL=/Brepro /pdbaltpath:myrkrshell.pdb

rem ---------------------------------------------------------------------------
rem Static checkers (tools\, ported from Vordr).  Advisory by default; "build
rem strict" makes any finding fail the build.  Skipped silently when python is
rem not on PATH.
rem   framecheck - WINCALL stack-arg spills that overflow a proc's frame (the
rem                raw-proc return-address-smash class: every proc in gui.asm is
rem                raw, so this is the one that matters most here)
rem   constcheck - an `equ` that disagrees between modules
rem   deadcode   - orphaned proc/data/equ/macro symbols
rem   wstrcheck  - a bounded copy (wcopy) called without its r8 bound
rem   aligncheck - odd-address wide strings handed to -W APIs, and oversized
rem                `dup (?)` arrays sitting in .data instead of .data?
rem   wincallcheck - a WINCALL argument that reads a register the macro has
rem                already overwritten (it assigns r9, r8, rdx, rcx in that
rem                order, so arg1 must not read rdx/r8/r9).  PowerShell, not
rem                Python; it queries the same tools\floors.py for its floor.
rem Each also enforces a coverage floor (tools\floors.py) so a checker that
rem stops LOOKING cannot pass as a checker that found nothing.
rem ---------------------------------------------------------------------------
where python >nul 2>nul
if errorlevel 1 goto :nochk

echo === framecheck ===
rem --strict also counts warns: the tree is at zero, and gating keeps a new
rem local/outgoing-area overlap from accumulating back into an ignored list.
set FCFLAGS=
if "%STRICT%"=="1" set FCFLAGS=--strict
python tools\framecheck.py %FCFLAGS%
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo framecheck: frame bug or unreviewed overlap - failing strict build
        goto :failed
    )
    echo framecheck: WARNING - findings above; build continues. Use "build strict" to gate.
)
echo === constcheck ===
python tools\constcheck.py
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo constcheck: a constant disagrees across modules - failing strict build
        goto :failed
    )
    echo constcheck: WARNING - cross-module drift above; build continues. Use "build strict" to gate.
)
echo === deadcode ===
python tools\deadcode.py
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo deadcode: dead proc/data/equ - failing strict build
        goto :failed
    )
    echo deadcode: WARNING - dead symbols above; build continues. Use "build strict" to gate.
)
echo === wstrcheck ===
python tools\wstrcheck.py
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo wstrcheck: a bounded copy called without its bound - failing strict build
        goto :failed
    )
    echo wstrcheck: WARNING - unbounded call sites above; build continues. Use "build strict" to gate.
)
echo === aligncheck ===
python tools\aligncheck.py
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo aligncheck: misaligned wide-string labels - failing strict build
        goto :failed
    )
    echo aligncheck: WARNING - misaligned labels above; build continues. Use "build strict" to gate.
)
echo === menu bitmap ===
rem menu16.bmp is GENERATED from myrkr.ico and committed, so it can silently stop
rem matching: change the icon, forget the step, and the context menu keeps the
rem old picture with nothing reporting it.  Skips quietly when Pillow is absent.
python tools\make_menu_bmp.py --check
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo make_menu_bmp: menu16.bmp is stale - failing strict build
        goto :failed
    )
    echo make_menu_bmp: WARNING - menu16.bmp is stale; build continues. Use "build strict" to gate.
)
echo === wincallcheck ===
rem WINCALL assigns its register arguments in REVERSE (r9, r8, rdx, rcx), so an
rem earlier argument that reads a later argument's register sees the NEW value.
rem This checker existed for a year without ever running here: it had the tree's
rem path hardcoded and always exited 0, so it could neither be run elsewhere nor
rem gate anything.  Both fixed; a checker nothing invokes reads exactly like a
rem checker that found nothing.
powershell -NoProfile -ExecutionPolicy Bypass -File tools\wincallcheck.ps1
if errorlevel 1 (
    if "%STRICT%"=="1" (
        echo wincallcheck: WINCALL argument reads a clobbered register - failing strict build
        goto :failed
    )
    echo wincallcheck: WARNING - suspect WINCALL sites above; build continues. Use "build strict" to gate.
)
:nochk

set ASMFLAGS=/c /nologo /W3 /Zi %ASMEXTRA%
set SOURCES=main console hardening random loadcfg sha256 aesgcm blake2b argon2 fileio volume secmem secdesk cmd archive pack compress progress crc32 sha1 inflate deflate unzip zip selftest redteam log ramlog estream gui
rem shellext.asm is NOT in SOURCES: it is the whole of the second binary
rem (myrkrshell.dll) and shares no object with the exe.  It is assembled with
rem the same flags but linked separately, below.
set DLLSOURCES=shellext

echo === assembling ===
for %%f in (%SOURCES% %DLLSOURCES%) do (
    ml64 %ASMFLAGS% /Foobj\%%f.obj /Flobj\%%f.lst /I src src\%%f.asm
    if errorlevel 1 goto :failed
)

rem ---------------------------------------------------------------------------
rem Windows SDK paths.  The version is resolved at build time: the newest 10.*
rem dir under the SDK's Lib (dir /o-n = newest name first) wins, with the pinned
rem version as fallback if the enumeration finds nothing.  The tools (ml64/rc/
rem link) must be on PATH; passing the SDK include dirs to rc.exe explicitly
rem means this script builds from a plain prompt too, not only from an
rem "x64 Native Tools Command Prompt" that pre-sets the INCLUDE variable.
rem ---------------------------------------------------------------------------
set SDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0
for /f %%v in ('dir /b /ad /o-n "%SDKROOT%\Lib\10.*" 2^>nul') do (
    set SDKVER=%%v
    goto :sdkver_done
)
:sdkver_done
set SDKLIB=%SDKROOT%\Lib\%SDKVER%\um\x64
set SDKBIN=%SDKROOT%\bin\%SDKVER%\x64
set SDKINC=%SDKROOT%\Include\%SDKVER%
if exist "%SDKBIN%\mt.exe" set PATH=%SDKBIN%;%PATH%

echo === resource (VERSIONINFO + icon) ===
rc /nologo /I "%SDKINC%\um" /I "%SDKINC%\shared" /I "%SDKINC%\ucrt" /fo obj\myrkr.res myrkr.rc
if errorlevel 1 goto :failed
rc /nologo /I "%SDKINC%\um" /I "%SDKINC%\shared" /I "%SDKINC%\ucrt" /fo obj\myrkrshell.res myrkrshell.rc
if errorlevel 1 goto :failed

echo === linking myrkr.exe (%GUARDFLAGS%) ===
link /nologo /subsystem:windows /entry:wstart /nodefaultlib /incremental:no ^
     /dynamicbase /highentropyva /nxcompat /largeaddressaware ^
     %GUARDFLAGS% %REPROFLAGS% /debug /pdb:bin\myrkr.pdb /map:bin\myrkr.map ^
     /manifest:embed /manifestinput:myrkr.manifest /manifestuac:no ^
     /libpath:"%SDKLIB%" ^
     /out:bin\myrkr.exe obj\main.obj obj\console.obj obj\hardening.obj obj\random.obj obj\loadcfg.obj obj\sha256.obj obj\aesgcm.obj obj\blake2b.obj obj\argon2.obj obj\fileio.obj obj\volume.obj obj\secmem.obj obj\secdesk.obj obj\cmd.obj obj\archive.obj obj\pack.obj obj\compress.obj obj\progress.obj obj\crc32.obj obj\sha1.obj obj\inflate.obj obj\deflate.obj obj\unzip.obj obj\zip.obj obj\selftest.obj obj\redteam.obj obj\log.obj obj\ramlog.obj obj\estream.obj obj\gui.obj obj\myrkr.res ^
     kernel32.lib bcrypt.lib cabinet.lib user32.lib comdlg32.lib comctl32.lib shell32.lib ole32.lib gdi32.lib advapi32.lib uxtheme.lib msimg32.lib
if errorlevel 1 goto :failed

rem ---------------------------------------------------------------------------
rem myrkrshell.dll - the drag-drop shell extension (src\shellext.asm).
rem
rem A separate link, not a second object in the exe: this DLL is loaded into
rem explorer.exe, so everything in it is reachable from a process we do not own.
rem Keeping it to one source file with four imported libraries is the point.
rem
rem /entry:DllMain      - no CRT, so no _DllMainCRTStartup to run
rem /def:myrkrshell.def - exports DllGetClassObject + DllCanUnloadNow, and
rem                       NOT DllRegisterServer: the MSI writes the registry
rem /noentry is NOT used - DllMain has to capture hinstDLL, which is how
rem                       InvokeCommand finds myrkr.exe next to this DLL
rem
rem The exe's loadcfg.obj is deliberately not linked in: it names `start` (the
rem exe entry point) in its CFG function table.  This image carries no load
rem config, which is consistent - /guard:cf is off here for the same reason it
rem is off for the exe (no per-function metadata from hand-written MASM).
rem ---------------------------------------------------------------------------
echo === linking myrkrshell.dll (%GUARDFLAGS%) ===
link /nologo /dll /entry:DllMain /nodefaultlib /incremental:no ^
     /dynamicbase /highentropyva /nxcompat ^
     %GUARDFLAGS% %REPROFLAGS_DLL% /debug /pdb:bin\myrkrshell.pdb /map:bin\myrkrshell.map ^
     /def:myrkrshell.def /implib:obj\myrkrshell.lib /libpath:"%SDKLIB%" ^
     /out:bin\myrkrshell.dll obj\shellext.obj obj\myrkrshell.res ^
     kernel32.lib user32.lib shell32.lib ole32.lib
if errorlevel 1 goto :failed

echo === mitigation check (optional, needs dumpbin) ===
dumpbin /headers bin\myrkr.exe | findstr /i "Dynamic NX Guard CET High" 2>nul
dumpbin /headers bin\myrkrshell.dll | findstr /i "Dynamic NX Guard CET High" 2>nul

if "%REPRO%"=="1" (
    rem ---------------------------------------------------------------------
    rem Normalise BEFORE hashing.  /Brepro replaces timestamps with a hash of
    rem the linker's inputs, but ml64 stamps every .obj and this script
    rem reassembles all of them on every run - so the inputs differ each time
    rem and the "deterministic" stamp differs with them.  Two builds of one
    rem commit came out 73 bytes apart, both claiming 1.0.23.0.  pe_normalise
    rem zeroes those fields so the published hash means something.
    rem
    rem This step used to say "verify against a fresh rebuild" and then print
    rem two hashes at a human.  It compared nothing, which is why the drift
    rem above went unnoticed for the whole of 1.0.9 .. 1.0.23.  The actual
    rem comparison lives in tools\verify_repro.ps1, which builds twice.
    rem ---------------------------------------------------------------------
    echo === release: normalise build timestamps, then publish SHA-256 ===
    python tools\pe_normalise.py bin\myrkr.exe bin\myrkrshell.dll
    if errorlevel 1 goto :failed
    rem findstr /v ":" drops certutil's "SHA256 hash of ..." and "CertUtil: ..."
    rem lines; the /r "^$" pass drops the blank one it puts between them.  The
    rem obvious filter, /r "^[0-9a-f]", does NOT work: findstr's bracket ranges
    rem match case-insensitively, so "CertUtil:" survives it.
    echo myrkr.exe> bin\SHA256SUMS.txt
    certutil -hashfile bin\myrkr.exe SHA256 | findstr /v ":" | findstr /r /v "^$" >> bin\SHA256SUMS.txt
    echo myrkrshell.dll>> bin\SHA256SUMS.txt
    certutil -hashfile bin\myrkrshell.dll SHA256 | findstr /v ":" | findstr /r /v "^$" >> bin\SHA256SUMS.txt
    type bin\SHA256SUMS.txt
    echo     ^(recorded in bin\SHA256SUMS.txt; run tools\verify_repro.ps1 to prove it reproduces^)
)

echo.
echo BUILD OK: bin\myrkr.exe + bin\myrkrshell.dll
exit /b 0

:failed
echo.
echo BUILD FAILED
exit /b 1

