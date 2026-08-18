<#
    make_msi.ps1 - build a per-machine MSI around bin\myrkr.exe.

    No third-party toolchain: the MSI database is authored directly through the
    WindowsInstaller COM automation and the payload is packed with makecab.
    Requiring WiX to cut a release would undercut "no external dependencies".

    WHAT IT INSTALLS, and just as importantly what it does not:

      * two files, myrkr.exe and myrkrshell.dll, into %ProgramFiles%\Myrkr
      * a Start Menu shortcut
      * an Add/Remove Programs entry carrying ProductName + ProductVersion
      * HKLM policy values - ONLY those the installing admin asks for by name
      * the .mrk file association          (MYRKR_NOASSOC=1 to skip)
      * Explorer context-menu verbs        (MYRKR_NOCONTEXT=1 to skip)
      * the drag-drop handler's COM registration (MYRKR_NOSHELLEXT=1 to skip)

    It owns NOTHING else.  No user data, no HKCU settings.  That is deliberate:
    uninstall removes only what MSI installed, so a user who removes Myrkr keeps
    their containers and their preferences.  There is no RemoveFile table and
    there must never be - one row aimed at the wrong directory is all it takes to
    delete the encrypted files the tool exists to protect.

    POLICY (see $Policies).  Every HKLM value load_settings reads is exposed as a
    public MSI property:

        msiexec /i myrkr-1.0.0.msi /qn MYRKR_MINLEN=16 MYRKR_LOGLEVEL=3

    Each lives in its own component conditioned on its property, so a value the
    admin did not name is not written.  That matters more than it looks: in Myrkr
    the PRESENCE of an HKLM value is what locks the setting against the user
    (load_settings sets g_lock_* for anything it finds while g_loading_hklm is
    set).  An installer that helpfully wrote every default would hand the admin a
    machine where the user can change nothing.

    Values are not validated here - they arrive at install time, not build time.
    load_settings clamps every one on read, so a typo degrades to the clamp
    rather than to undefined behaviour.

    CAVEAT: MSI does not remember properties.  An upgrade that does not repeat
    them installs without those components, and the old product's values go away
    with it - so policy must be passed on EVERY install, upgrades included.

    PER-MACHINE: installs into Program Files, so install and uninstall need
    elevation.  That is the only scope in which HKLM policy and machine-wide
    file associations can be registered.  It does not contradict myrkr.manifest's
    asInvoker, which governs how the program RUNS, not how it is installed.

    The version is read from the exe's own version resource, so myrkr.rc stays
    the single source of truth and the MSI cannot drift from the binary it wraps.

    Usage:  powershell -ExecutionPolicy Bypass -File tools\make_msi.ps1
            [-Exe bin\myrkr.exe] [-Dll bin\myrkrshell.dll] [-OutDir bin]
#>
[CmdletBinding()]
param(
    [string]$Exe    = "bin\myrkr.exe",
    [string]$Dll    = "bin\myrkrshell.dll",
    [string]$OutDir = "bin",
    # Normally a fresh ProductCode per build - that is what tells Windows the
    # payload differs, and RemoveExistingProducts depends on it.
    #
    # Pin it only to REPAIR an already-installed product whose cached package is
    # broken.  A custom action that fails takes the whole sequence with it, and
    # because RemoveExistingProducts runs the OLD product's sequence, a bad
    # action blocks its own removal: upgrade and uninstall both fail 1603 and
    # roll back.  Building with the stuck ProductCode and running
    # "msiexec /fvomus" re-caches the fixed package over it and breaks the loop.
    [string]$ProductCodeOverride = "",
    [string]$OutFile = ""
)

$ErrorActionPreference = "Stop"

# Stable identity.  UpgradeCode must NEVER change - it is what lets a new MSI
# recognise and replace an older install instead of sitting beside it.
# ProductCode is regenerated per build, which is what tells Windows the payload
# differs (required for RemoveExistingProducts to do its job).
$UpgradeCode   = "{9C4E2B17-58A3-4D6E-B1F0-3E7A9D2C4F86}"
$ComponentGuid = "{1A7F3D52-6B8E-4C90-A2D1-5F0E8B3C7A94}"
$Manufacturer  = "Thomas Smistad"
$ProductName   = "Myrkr"
$InstallDir    = "Myrkr"
$PolicyKey     = "SOFTWARE\Myrkr"      # gui.asm w_regkey - HKLM wins over HKCU
$ClassesKey    = "SOFTWARE\Classes"
$DefaultsKey   = "SOFTWARE\Myrkr\Defaults"   # gui.asm w_regkey_def - deployed, not locked

# The HKLM policy surface, one row per value load_settings reads.  Value/Range/
# Default mirror gui.asm; keep them in step, since this table is what an
# administrator reads before deploying.
#
# Guid is the COMPONENT id and must never change: it is what lets an upgrade
# recognise the value it already owns instead of orphaning it.
$Policies = @(
    @{ Prop="MYRKR_MINLEN";     Value="MinLen";     Comp="PolMinLen";     Guid="{3E9A1C74-2D5B-4F86-9C03-7B1E5A8D2F60}"; Range="1-256"; Default="12"; Doc="minimum password length" }
    @{ Prop="MYRKR_MINCLASSES"; Value="MinClasses"; Comp="PolMinClasses"; Guid="{5B2D7F91-8A4C-4E30-B6D5-1F9C3E7A0B48}"; Range="0-4";   Default="3";  Doc="character classes a password must mix (0 disables the policy)" }
    @{ Prop="MYRKR_LOGLEVEL";   Value="LogLevel";   Comp="PolLogLevel";   Guid="{7C4E0A26-9F31-4B85-8D72-2A6B4F1E9C53}"; Range="0-4";   Default="0";  Doc="audit-log verbosity: 0 off, 1 error, 2 warning, 3 full, 4 debug (paths)" }
    @{ Prop="MYRKR_COMPRESS";   Value="Compress";   Comp="PolCompress";   Guid="{2F8B6D40-1E7A-4C93-A5B8-9D0C3E6F2A71}"; Range="0/1";   Default="size-based"; Doc="force compression on (1) or off (0), overriding the 50 MiB default" }
    @{ Prop="MYRKR_FORMAT";     Value="Format";     Comp="PolFormat";     Guid="{8D3C5E72-4B90-4A16-92F7-6E1A8C5D0B39}"; Range="0/1";   Default="0";  Doc="output format: 0 = .mrk container, 1 = WinZip-AES .zip" }
)

# --- the DEFAULTS surface, one row per value, HKLM\SOFTWARE\Myrkr\Defaults ----
# Same values, opposite meaning.  A value under the POLICY key above is enforced:
# myrkr reads it last and greys the control out.  A value here is only where the
# setting STARTS - the user may change it, and their change goes to HKCU, which
# beats this on the next run.
#
# So an administrator who wants Zip to be the default on new machines says
# MYRKR_DEF_FORMAT=1, and one who wants Zip and no argument about it says
# MYRKR_FORMAT=1.  Both, and the policy wins.
#
# HKLM rather than HKCU deliberately.  A per-machine MSI writing HKCU only
# reaches the account that happened to run msiexec - every other user on the
# machine gets nothing, and repairing that needs advertised components and
# self-repair, which is a lot of moving parts to deliver one default.  A value
# here is read by every user and overridden by any of them.
$Defaults = @(
    @{ Prop="MYRKR_DEF_MINLEN";      Value="MinLen";        Comp="DefMinLen";      Guid="{6B1D4A83-0C57-4E92-9A38-D5F27C4E1B60}"; Doc="starting minimum password length" }
    @{ Prop="MYRKR_DEF_MINCLASSES";  Value="MinClasses";    Comp="DefMinClasses";  Guid="{9E3F7C21-4D68-40B5-8172-A6C0B9D53E47}"; Doc="starting character-class requirement" }
    @{ Prop="MYRKR_DEF_LOGLEVEL";    Value="LogLevel";      Comp="DefLogLevel";    Guid="{2A8C5E90-7B14-4F63-B0D9-3E5A1C7F8B26}"; Doc="starting audit-log verbosity" }
    @{ Prop="MYRKR_DEF_COMPRESS";    Value="Compress";      Comp="DefCompress";    Guid="{4D0B9F35-1A62-4C87-95E3-8B7C2D6A0F51}"; Doc="starting compression choice (0/1)" }
    @{ Prop="MYRKR_DEF_FORMAT";      Value="Format";        Comp="DefFormat";      Guid="{7F5A2C68-3E90-4B14-A7D6-0C9E4B8F3A25}"; Doc="starting output format: 0 = .mrk, 1 = .zip" }
    @{ Prop="MYRKR_DEF_SECUREDESK";  Value="SecureDesktop"; Comp="DefSecureDesk";  Guid="{1C6E8B47-52A0-4D39-86F5-7A3D9C0E2B84}"; Doc="starting private-desktop choice (0/1)" }
    @{ Prop="MYRKR_DEF_KDFTIME";     Value="KdfTime";       Comp="DefKdfTime";     Guid="{8A4D0F72-6C31-4E58-B9A2-5D1F7B3C9E60}"; Doc="starting Argon2 time cost" }
    @{ Prop="MYRKR_DEF_KDFMEMORY";   Value="KdfMemory";     Comp="DefKdfMemory";   Guid="{3B9C7E14-0A85-4F26-91D7-6E2A8C5B4D03}"; Doc="starting Argon2 memory cost, MiB" }
    @{ Prop="MYRKR_DEF_SPLITSIZE";   Value="SplitSize";     Comp="DefSplitSize";   Guid="{5E2A8D06-9F43-4B71-A85C-0D7B6E1F4C92}"; Doc="starting File split preset INDEX (0 = off)" }
)

# --- SecureDesktop: the one policy value written whether or not it is named ---
# Every entry in $Policies above is conditioned on its property, so a value the
# admin did not ask for is not written - because in Myrkr the PRESENCE of an
# HKLM value is what locks it, and writing every default would hand out machines
# where the user can change nothing.
#
# SecureDesktop is deliberately the exception.  It decides whether the password
# is typed on a private desktop, which is the control that stops an
# authorized-but-abused Myrkr being driven headlessly across an estate; leaving
# it merely DEFAULTED would mean it is enforced only where an administrator
# remembered to name it.  So the component is unconditional and the property
# defaults to 1: the value is always present, always locked, and the admin
# chooses which way it is locked.
#
#   (default)                        -> SecureDesktop = 1  (enforced)
#   MYRKR_SECUREDESKTOP=0            -> SecureDesktop = 0  (ordinary prompt)
#
# The cost of the second form is in manifest section 14: it restores the
# window-message surface that the private desktop exists to remove.
$SdProp  = "MYRKR_SECUREDESKTOP"
$SdValue = "SecureDesktop"
$SdComp  = "PolSecureDesk"
$SdGuid  = "{0C7A45E1-9B32-4D68-A0F4-6E2D95B18C37}"

# --- .mrk file association ---------------------------------------------------
$AssocComp = "FileAssoc"
$AssocGuid = "{4A9E1B58-7C20-4D36-B8F1-0E5A3D9C7B24}"
$AssocProp = "MYRKR_NOASSOC"
$ProgId    = "Myrkr.Container"

# --- Explorer context menus ---------------------------------------------------
# These were four classic "%1" verbs.  They are gone, because %1 is per-FILE:
# selecting four files and invoking the verb made Windows launch four myrkr.exe
# instances, which meant four password prompts and four single-file containers.
# That was documented as a caveat and observed in testing to be exactly as
# confusing as it sounds.
#
# The same DLL that serves the right-DRAG menu already implements IShellExtInit +
# IContextMenu and already reads the whole selection out of CF_HDROP, so
# registering it under shellex\ContextMenuHandlers makes a right-CLICK behave
# like a right-drag: one window, the whole selection, one prompt.  The handler
# tells the two apart by pidlFolder - non-NULL is a drop target and adds --to;
# NULL is a right-click and the output lands beside the source, as before.
#
# Registered on * (every file) and Directory, but NOT Drive: offering to encrypt
# a whole drive from a right-click is not something to put one slip away.
$CtxComp = "CtxHandler"
# New component identity, not the old CtxMenu GUID: the key path and the
# resources both changed, and reusing a component GUID for a different set of
# resources is precisely what the component rules forbid.  The old rows go away
# with RemoveExistingProducts on upgrade.
$CtxGuid = "{3B6F1A94-8C25-4D70-9E13-64A0D2F857BC}"
$CtxProp = "MYRKR_NOCONTEXT"

# --- drag-drop shell extension -------------------------------------------------
# myrkrshell.dll adds "Encrypt" / "Decrypt here" to the menu Explorer shows when
# files are RIGHT-dragged onto a folder, which is the only way to hand a whole
# multi-file selection to ONE myrkr.exe (the %1 verbs above launch one window per
# file).  It is an in-process COM server: Explorer loads it into itself.
#
# The file and its registration are ONE component, and MYRKR_NOSHELLEXT=1
# suppresses both.  Deliberately not two: an opt-out that left the DLL in Program
# Files would be a weaker statement than it looks, and a registration that
# outlived the file would point Explorer at a missing in-proc server on every
# folder drag.  Opting out means the binary is not on the machine at all.
$ShellComp = "ShellExt"
$ShellGuid = "{5D8C2A63-4F71-4B08-9E35-7A1D6C0B4E29}"
$ShellProp = "MYRKR_NOSHELLEXT"
# Must match CLSID_MyrkrDrop in src\shellext.asm.  Changing either orphans the
# other: the DLL answers DllGetClassObject for exactly this class, and these keys
# are the only thing that tells Explorer to ask.
$DropClsid = "{7C4A6E10-2F58-4B3D-9C81-5E0A7D9B4F62}"
$DropName  = "Myrkr"                    # our entry under DragDropHandlers
$DropDesc  = "Myrkr drag-drop handler"

function Resolve-Full([string]$p) {
    if ([System.IO.Path]::IsPathRooted($p)) { $p } else { Join-Path (Get-Location) $p }
}

$exePath = Resolve-Full $Exe
if (-not (Test-Path $exePath)) { throw "not found: $exePath  (build first: build.cmd strict)" }
$dllPath = Resolve-Full $Dll
if (-not (Test-Path $dllPath)) { throw "not found: $dllPath  (build first: build.cmd strict)" }

# --- refuse to wrap anything but a release build ------------------------------
# Two build flavours must never be packaged, and nothing about the file says
# which one it is - same name, same version resource, same icons:
#
#   DBG_TRACE  compiles in the `redteam` verb, a binary that deliberately
#              corrupts its own stack on request.
#   TEST_IO    accepts a password on the COMMAND LINE.  The release build
#              refuses the five password-taking verbs precisely so that an
#              authorized-but-abused Myrkr cannot be driven across an estate by
#              a script; shipping a test build would hand out that surface and
#              silently undo the control.
#
# Each leaves a marker string compiled in only under its flag, so scan the image
# as UTF-16LE rather than executing anything.  Running the verb to find out is
# not an option: in a release build the name is not recognised, so the hybrid
# entry point would treat it as a dropped file and open a GUI during packaging.
$bytes = [IO.File]::ReadAllBytes($exePath)
function Test-Marker([byte[]]$hay, [string]$text) {
    $n = [Text.Encoding]::Unicode.GetBytes($text)
    for ($i = 0; $i -le $hay.Length - $n.Length; $i++) {
        if ($hay[$i] -ne $n[0]) { continue }
        $hit = $true
        for ($j = 1; $j -lt $n.Length; $j++) {
            if ($hay[$i+$j] -ne $n[$j]) { $hit = $false; break }
        }
        if ($hit) { return $true }
    }
    return $false
}
if (Test-Marker $bytes "redteam") {
    throw "$exePath contains the DBG_TRACE-only 'redteam' verb - that is a debug build. Run build.cmd strict and package that."
}
if (Test-Marker $bytes "MYRKR_TEST_IO_BUILD") {
    throw "$exePath carries the TEST_IO marker - it accepts a password on the command line, which the release build deliberately does not. Run build.cmd strict and package that."
}

# --- and refuse a shell DLL that is not a COM server ---------------------------
# Registering a CLSID whose InprocServer32 cannot answer DllGetClassObject makes
# every folder drag in Explorer load a DLL that then does nothing, and the
# failure is silent - the menu item simply never appears.  The export names live
# in the DLL's export directory as plain ASCII, so this is a byte scan like the
# two above rather than a LoadLibrary of an unbuilt binary during packaging.
$dllBytes = [IO.File]::ReadAllBytes($dllPath)
function Test-Ascii([byte[]]$hay, [string]$text) {
    $n = [Text.Encoding]::ASCII.GetBytes($text)
    for ($i = 0; $i -le $hay.Length - $n.Length; $i++) {
        if ($hay[$i] -ne $n[0]) { continue }
        $hit = $true
        for ($j = 1; $j -lt $n.Length; $j++) {
            if ($hay[$i+$j] -ne $n[$j]) { $hit = $false; break }
        }
        if ($hit) { return $true }
    }
    return $false
}
foreach ($e in @("DllGetClassObject", "DllCanUnloadNow")) {
    if (-not (Test-Ascii $dllBytes $e)) {
        throw "$dllPath does not export $e - it is not a usable in-proc COM server. Run build.cmd strict and package that."
    }
}

# --- version comes from the binary, never typed twice ------------------------
$vi = (Get-Item $exePath).VersionInfo
$fv = $vi.FileVersion
if (-not $fv) { throw "$exePath has no version resource" }
$parts = ($fv -split '[.,]') | ForEach-Object { [int]$_ }
# MSI ProductVersion is max three fields; the 4th is ignored by Windows Installer
$productVersion = "{0}.{1}.{2}" -f $parts[0], $parts[1], $parts[2]
# Both binaries carry a version resource and constcheck keeps them in step at
# build time; re-check it here, because the MSI is what a machine ends up with
# and a mismatched pair is invisible once packaged.
$dllVer = (Get-Item $dllPath).VersionInfo.FileVersion
if (-not $dllVer) { throw "$dllPath has no version resource" }
$dllParts = ($dllVer -split '[.,]') | ForEach-Object { [int]$_ }
$dllMmp = "{0}.{1}.{2}" -f $dllParts[0], $dllParts[1], $dllParts[2]
if ($dllMmp -ne $productVersion) {
    throw "myrkrshell.dll is version $dllVer but myrkr.exe is $fv - one MSI must not install two binaries claiming different versions. Fix myrkrshell.rc / myrkr.rc and rebuild."
}
Write-Host ("  exe            : {0}" -f $exePath)
Write-Host ("  dll            : {0}" -f $dllPath)
Write-Host ("  FileVersion    : {0}  ->  MSI ProductVersion {1}" -f $fv, $productVersion)

$outMsi = Join-Path (Resolve-Full $OutDir) ("myrkr-{0}.msi" -f $productVersion)
if ($OutFile) { $outMsi = Resolve-Full $OutFile }
if (Test-Path $outMsi) { Remove-Item $outMsi -Force }

# --- pack the payload into a cab ---------------------------------------------
$work = Join-Path $env:TEMP ("myrkrmsi_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Copy-Item $exePath (Join-Path $work "myrkr.exe")
    Copy-Item $dllPath (Join-Path $work "myrkrshell.dll")
    $ddf = Join-Path $work "make.ddf"
@"
.OPTION EXPLICIT
.Set CabinetNameTemplate=myrkr.cab
.Set DiskDirectory1=$work
.Set Cabinet=on
.Set Compress=on
.Set CompressionType=MSZIP
.Set MaxDiskSize=0
.Set ReservePerCabinetSize=0
.Set InfFileName=$work\setup.inf
.Set RptFileName=$work\setup.rpt
"$work\myrkr.exe" myrkr.exe
"$work\myrkrshell.dll" myrkrshell.dll
"@ | Out-File -FilePath $ddf -Encoding ascii
    # makecab drops setup.inf / setup.rpt in the CURRENT directory unless told
    # otherwise, which would put build litter in the repo root.
    Push-Location $work
    $cabLog = & makecab.exe /F $ddf 2>&1
    Pop-Location
    $cab = Join-Path $work "myrkr.cab"
    if (-not (Test-Path $cab)) { throw "makecab failed:`n$cabLog" }
    Write-Host ("  cab            : {0} bytes" -f (Get-Item $cab).Length)

    # --- author the database -------------------------------------------------
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.OpenDatabase($outMsi, 3)      # msiOpenDatabaseModeCreate

    function Exec([string]$sql) {
        try {
            $view = $db.OpenView($sql)
            $view.Execute()
            $view.Close()
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
        } catch {
            # MSI reports every SQL failure as the same opaque "Execute,Params",
            # so the statement has to be surfaced or the error is unusable.
            throw ("MSI SQL failed:`n  {0}`n  -> {1}" -f $sql, $_.Exception.Message)
        }
    }

    Exec "CREATE TABLE ``Property`` (``Property`` CHAR(72) NOT NULL, ``Value`` CHAR(255) NOT NULL PRIMARY KEY ``Property``)"
    Exec "CREATE TABLE ``Directory`` (``Directory`` CHAR(72) NOT NULL, ``Directory_Parent`` CHAR(72), ``DefaultDir`` CHAR(255) NOT NULL PRIMARY KEY ``Directory``)"
    Exec "CREATE TABLE ``Component`` (``Component`` CHAR(72) NOT NULL, ``ComponentId`` CHAR(38), ``Directory_`` CHAR(72) NOT NULL, ``Attributes`` SHORT NOT NULL, ``Condition`` CHAR(255), ``KeyPath`` CHAR(72) PRIMARY KEY ``Component``)"
    Exec "CREATE TABLE ``Feature`` (``Feature`` CHAR(38) NOT NULL, ``Feature_Parent`` CHAR(38), ``Title`` CHAR(64), ``Description`` CHAR(255), ``Display`` SHORT, ``Level`` SHORT NOT NULL, ``Directory_`` CHAR(72), ``Attributes`` SHORT NOT NULL PRIMARY KEY ``Feature``)"
    Exec "CREATE TABLE ``FeatureComponents`` (``Feature_`` CHAR(38) NOT NULL, ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Feature_``, ``Component_``)"
    Exec "CREATE TABLE ``File`` (``File`` CHAR(72) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``FileName`` CHAR(255) NOT NULL, ``FileSize`` LONG NOT NULL, ``Version`` CHAR(72), ``Language`` CHAR(20), ``Attributes`` SHORT, ``Sequence`` SHORT NOT NULL PRIMARY KEY ``File``)"
    Exec "CREATE TABLE ``Media`` (``DiskId`` SHORT NOT NULL, ``LastSequence`` SHORT NOT NULL, ``DiskPrompt`` CHAR(64), ``Cabinet`` CHAR(255), ``VolumeLabel`` CHAR(32), ``Source`` CHAR(72) PRIMARY KEY ``DiskId``)"
    Exec "CREATE TABLE ``InstallExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``InstallUISequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``AdminExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``AdvtExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
    Exec "CREATE TABLE ``Upgrade`` (``UpgradeCode`` CHAR(38) NOT NULL, ``VersionMin`` CHAR(20), ``VersionMax`` CHAR(20), ``Language`` CHAR(255), ``Attributes`` LONG NOT NULL, ``Remove`` CHAR(255), ``ActionProperty`` CHAR(72) NOT NULL PRIMARY KEY ``UpgradeCode``, ``VersionMin``, ``VersionMax``, ``Language``, ``Attributes``)"
    Exec "CREATE TABLE ``Shortcut`` (``Shortcut`` CHAR(72) NOT NULL, ``Directory_`` CHAR(72) NOT NULL, ``Name`` CHAR(128) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``Target`` CHAR(72) NOT NULL, ``Arguments`` CHAR(255), ``Description`` CHAR(255), ``Hotkey`` SHORT, ``Icon_`` CHAR(72), ``IconIndex`` SHORT, ``ShowCmd`` SHORT, ``WkDir`` CHAR(72) PRIMARY KEY ``Shortcut``)"
    Exec "CREATE TABLE ``Registry`` (``Registry`` CHAR(72) NOT NULL, ``Root`` SHORT NOT NULL, ``Key`` CHAR(255) NOT NULL, ``Name`` CHAR(255), ``Value`` CHAR(0), ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Registry``)"
    Exec "CREATE TABLE ``CustomAction`` (``Action`` CHAR(72) NOT NULL, ``Type`` SHORT NOT NULL, ``Source`` CHAR(72), ``Target`` CHAR(255) PRIMARY KEY ``Action``)"
    # NO RemoveFile table.  MSI removes a component's own files automatically;
    # RemoveFile exists to delete things the installer did NOT install, which
    # here would mean deleting someone's encrypted containers.

    $productCode = "{" + [guid]::NewGuid().ToString().ToUpper() + "}"
    if ($ProductCodeOverride) {
        if ($ProductCodeOverride -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') {
            throw "not a well-formed ProductCode: $ProductCodeOverride"
        }
        $productCode = $ProductCodeOverride.ToUpper()
        Write-Host ("  ProductCode    : PINNED to {0} (repair build)" -f $productCode)
    }
    $secureProps = @("OLDERVERSIONBEINGUPGRADED", $AssocProp, $CtxProp, $ShellProp, $SdProp) +
                   ($Policies | ForEach-Object { $_.Prop }) +
                   ($Defaults | ForEach-Object { $_.Prop })
    $props = @{
        "ProductCode"        = $productCode
        "ProductName"        = $ProductName
        "ProductVersion"     = $productVersion
        "Manufacturer"       = $Manufacturer
        "UpgradeCode"        = $UpgradeCode
        "ProductLanguage"    = "1033"
        "ALLUSERS"           = "1"
        "ARPNOMODIFY"        = "1"
        "ARPNOREPAIR"        = "1"
        # Restart Manager is DISABLED, deliberately.  It exists to release files
        # held by running applications, and the file it would go after here is
        # myrkrshell.dll inside explorer.exe - so what it actually does is shut
        # down the shell.  Its restart is best effort and it does not always
        # manage it: over RDP it declines outright ("Application SID does not
        # match Conductor SID"), and on the console it has left this machine
        # with no desktop, no taskbar and no way to start anything.  Windows'
        # own safety net does not cover that either - AutoRestartShell fires
        # only when the shell exits UNEXPECTEDLY, and an RM shutdown is
        # graceful.
        #
        # Without RM, Windows Installer renames the old DLL aside and writes the
        # new one, which works while Explorer still has the old image mapped.
        # The cost is stated rather than hidden: the shell extension goes on
        # running the previous build until Explorer next restarts, and the
        # installer says a restart is required.  The EXE - which is all the
        # encryption and all the UI - is live immediately.
        #
        # Losing a desktop is a worse failure than a shell extension being one
        # restart behind, and unlike the stale DLL it is not something the user
        # can shrug off.
        "MSIRESTARTMANAGERCONTROL" = "Disable"
        # Public properties reach the elevated half of a per-machine install only
        # if they are listed here.  Miss one and it silently has no effect: the
        # property is set, the component condition still evaluates false.
        "SecureCustomProperties" = ($secureProps -join ";")
        # Default for the one always-written policy value.  A Property row is
        # what makes "#[MYRKR_SECUREDESKTOP]" resolve when the admin names
        # nothing; without it the registry value would be written empty.
        $SdProp                  = "1"
    }
    foreach ($k in $props.Keys) {
        $v = $props[$k] -replace "'", "''"
        Exec "INSERT INTO ``Property`` (``Property``,``Value``) VALUES ('$k','$v')"
    }

    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('TARGETDIR','','SourceDir')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('ProgramFiles64Folder','TARGETDIR','.')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('INSTALLDIR','ProgramFiles64Folder','$InstallDir')"
    Exec "INSERT INTO ``Directory`` (``Directory``,``Directory_Parent``,``DefaultDir``) VALUES ('ProgramMenuFolder','TARGETDIR','.')"
    # There is no System64Folder row.  There was one, for the shell-restart
    # guard's cmd.exe; the guard is gone (see MSIRESTARTMANAGERCONTROL above)
    # and the row went with it.  A directory-sourced custom action naming a
    # directory that is not in this table fails the install with error 2727 - so
    # if one is ever added back, its directory has to come back too.

    Exec "INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('MyrkrExe','$ComponentGuid','INSTALLDIR',0,'','myrkr.exe')"
    Exec "INSERT INTO ``Feature`` (``Feature``,``Feature_Parent``,``Title``,``Description``,``Display``,``Level``,``Directory_``,``Attributes``) VALUES ('Main','','Myrkr','Myrkr file encryption',1,1,'INSTALLDIR',0)"
    Exec "INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','MyrkrExe')"

    # --- one component per policy value --------------------------------------
    # Attributes 4 = the registry row is the key path; 256 = write to the 64-bit
    # view.  Without 256 an x64 package puts these under WOW6432Node, where the
    # 64-bit myrkr.exe would never look - the install appears to succeed and the
    # policy simply does not take effect.
    foreach ($p in $Policies) {
        $reg = "Reg" + $p.Comp
        Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'{2}','{3}')" -f $p.Comp, $p.Guid, $p.Prop, $reg)
        Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $p.Comp)
        # "#" makes it a REG_DWORD; the property supplies the decimal digits.
        Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_``) VALUES ('{0}',2,'{1}','{2}','#[{3}]','{4}')" -f $reg, $PolicyKey, $p.Value, $p.Prop, $p.Comp)
    }
    Write-Host ("  policy values  : {0} exposed as properties" -f $Policies.Count)

    # --- one component per DEFAULT value -------------------------------------
    # Identical shape to the policy rows above and a different key: these are
    # read by myrkr with the lock flag clear, so they set a starting value and
    # grey nothing out.  Conditioned on the property for the same reason the
    # policy rows are - a default nobody asked for is still a value written into
    # every user's settings, and the built-in default is the better answer.
    foreach ($d in $Defaults) {
        $reg = "Reg" + $d.Comp
        Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'{2}','{3}')" -f $d.Comp, $d.Guid, $d.Prop, $reg)
        Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $d.Comp)
        Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_``) VALUES ('{0}',2,'{1}','{2}','#[{3}]','{4}')" -f $reg, $DefaultsKey, $d.Value, $d.Prop, $d.Comp)
    }
    Write-Host ("  default values : {0} exposed as properties (deployed, not locked)" -f $Defaults.Count)

    # --- SecureDesktop: unconditional component (see the note above) ---------
    # Condition is EMPTY, unlike every entry in $Policies: this one installs
    # whether or not the admin names it, so the estate is protected by default
    # rather than by remembering.
    Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'','Reg{0}')" -f $SdComp, $SdGuid)
    Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $SdComp)
    Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_``) VALUES ('Reg{0}',2,'{1}','{2}','#[{3}]','{0}')" -f $SdComp, $PolicyKey, $SdValue, $SdProp)
    Write-Host ("  secure desktop : {0} always written (default 1; {1}=0 to allow the ordinary prompt)" -f $SdValue, $SdProp)

    # A null Name column is how the Registry table writes a key's DEFAULT value,
    # so these leave Name out entirely rather than passing an empty string - an
    # empty Name would create a value literally called "".
    function RegDefault([string]$key, [string]$path, [string]$value, [string]$comp) {
        $v = $value -replace "'", "''"
        Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Value``,``Component_``) VALUES ('{0}',2,'{1}','{2}','{3}')" -f $key, $path, $v, $comp)
    }
    function RegNamed([string]$key, [string]$path, [string]$name, [string]$value, [string]$comp) {
        $v = $value -replace "'", "''"
        Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_``) VALUES ('{0}',2,'{1}','{2}','{3}','{4}')" -f $key, $path, $name, $v, $comp)
    }
    # Name "-" deletes the key and everything under it on uninstall.
    function RegRemoveTree([string]$key, [string]$path, [string]$comp) {
        Exec ("INSERT INTO ``Registry`` (``Registry``,``Root``,``Key``,``Name``,``Component_``) VALUES ('{0}',2,'{1}','-','{2}')" -f $key, $path, $comp)
    }

    # "%1" is literal here - MSI's Formatted syntax reserves [] and {}, not %.
    # The quotes matter: without them a path containing a space arrives as several
    # arguments and only the first fragment is seen.
    $cmd = '"[INSTALLDIR]myrkr.exe" "%1"'
    # ",N" indexes the exe's icon GROUPS in resource-id order (myrkr.rc): id 1 is
    # index 0, id 2 is index 1.  The file type gets index 1 so a .mrk is
    # recognisable in Explorer without being read.  There is no icon row for the
    # context menu any more: the entry is drawn by the handler, not by a registry
    # verb, so index 0 (the application icon) is no longer referenced here.
    $icoFile = '[INSTALLDIR]myrkr.exe,1'

    # --- .mrk association ----------------------------------------------------
    Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'NOT {2}','RegAssocExt')" -f $AssocComp, $AssocGuid, $AssocProp)
    Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $AssocComp)
    RegDefault "RegAssocExt"    "$ClassesKey\.mrk"                      $ProgId                       $AssocComp
    RegDefault "RegAssocProgId" "$ClassesKey\$ProgId"                   "Myrkr encrypted container"   $AssocComp
    RegDefault "RegAssocIcon"   "$ClassesKey\$ProgId\DefaultIcon"       $icoFile                      $AssocComp
    RegDefault "RegAssocCmd"    "$ClassesKey\$ProgId\shell\open\command" $cmd                         $AssocComp
    # Aimed at the ProgId we created and nothing else.  Deliberately NOT aimed at
    # the .mrk key itself, which another application may have added itself to.
    #
    # Note what this does and does not promise.  MSI still removes the VALUE we
    # wrote under .mrk, and deletes the key if that leaves it empty - verified on
    # a real uninstall, where .mrk did disappear.  That is correct: the point is
    # never to delete a key we do not exclusively own, not to leave an empty one
    # behind.  Where another application has written there too, its values keep
    # the key alive.
    RegRemoveTree "RegAssocClean" "$ClassesKey\$ProgId" $AssocComp
    Write-Host ("  file assoc     : .mrk -> {0} (skip with {1}=1)" -f $ProgId, $AssocProp)

    # --- context-menu handler ------------------------------------------------
    # Conditioned on BOTH properties: the rows name a CLSID whose in-proc server
    # is myrkrshell.dll, so suppressing the DLL has to suppress these too or the
    # shell would be pointed at a server that is not installed.
    $ctxCond = "NOT $CtxProp AND NOT $ShellProp"
    Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',260,'{2}','RegCtxAllFiles')" -f $CtxComp, $CtxGuid, $ctxCond)
    Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $CtxComp)

    # Row keys carry the "Reg" prefix because the component's KeyPath above names
    # one of them.  A KeyPath that matches no Registry row is not a build error:
    # Windows Installer falls back to looking the name up in the File table, does
    # not find it there either, and fails the INSTALL with error 2715.
    $ctxKeys = @(
        @("RegCtxAllFiles", "*"),
        @("RegCtxDirs",     "Directory")
    )
    foreach ($c in $ctxKeys) {
        $id = $c[0]
        $key = "$ClassesKey\$($c[1])\shellex\ContextMenuHandlers\$DropName"
        RegDefault $id $key $DropClsid $CtxComp
        RegRemoveTree ($id + "Clean") $key $CtxComp
    }
    if ($ctxKeys[0][0] -ne "RegCtxAllFiles") {
        throw "the CtxHandler KeyPath is hard-coded as RegCtxAllFiles; the first row is no longer that"
    }
    Write-Host ("  context menu   : handler on {0} (skip with {1}=1)" -f
                (($ctxKeys | ForEach-Object { $_[1] }) -join ", "), $CtxProp)

    # --- drag-drop shell extension -------------------------------------------
    # ONE component owning both the DLL and its registration (see the note at the
    # top).  KeyPath is the FILE, so Attributes carries 256 (64-bit view) but NOT
    # 4 (registry key path) - a 64-bit in-proc server must be registered under the
    # native CLSID key, never WOW6432Node, or 64-bit Explorer never finds it.
    Exec ("INSERT INTO ``Component`` (``Component``,``ComponentId``,``Directory_``,``Attributes``,``Condition``,``KeyPath``) VALUES ('{0}','{1}','INSTALLDIR',256,'NOT {2}','myrkrshell.dll')" -f $ShellComp, $ShellGuid, $ShellProp)
    Exec ("INSERT INTO ``FeatureComponents`` (``Feature_``,``Component_``) VALUES ('Main','{0}')" -f $ShellComp)

    $clsidKey = "$ClassesKey\CLSID\$DropClsid"
    RegDefault "RegShellClsid" $clsidKey                     $DropDesc                    $ShellComp
    RegDefault "RegShellInproc" "$clsidKey\InprocServer32"   '[INSTALLDIR]myrkrshell.dll' $ShellComp
    # Apartment is what the shell expects of a context-menu handler; it is also
    # what this DLL is written for - it takes no locks beyond the interlocked
    # refcounts and does no work on the calling thread.
    RegNamed "RegShellThread" "$clsidKey\InprocServer32" "ThreadingModel" "Apartment" $ShellComp

    # Directory AND Drive: they are siblings, not parent and child, so a handler
    # registered only under Directory never fires when files are dragged onto a
    # drive root.  Registering under their shared parent "Folder" as well would
    # offer the verb twice on an ordinary folder.
    foreach ($cls in @("Directory", "Drive")) {
        $ddk = "$ClassesKey\$cls\shellex\DragDropHandlers\$DropName"
        RegDefault ("RegShellDD" + $cls) $ddk $DropClsid $ShellComp
        RegRemoveTree ("RegShellDD" + $cls + "Clean") $ddk $ShellComp
    }
    # The Approved list is only consulted when the EnforceShellExtensionSecurity
    # policy is on - but where it IS on, an unlisted handler is silently never
    # loaded, which looks exactly like a handler that does not work.
    $approvedKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
    RegNamed "RegShellApproved" $approvedKey $DropClsid $DropDesc $ShellComp
    # Aimed at the CLSID we created and nothing else.
    RegRemoveTree "RegShellClsidClean" $clsidKey $ShellComp
    Write-Host ("  shell ext      : {0} -> myrkrshell.dll, Directory + Drive (skip with {1}=1)" -f $DropClsid, $ShellProp)

    # Sequence must match the order the files were fed to makecab above, or the
    # installer extracts the cab members into each other's names.
    $size = (Get-Item $exePath).Length
    Exec "INSERT INTO ``File`` (``File``,``Component_``,``FileName``,``FileSize``,``Version``,``Language``,``Attributes``,``Sequence``) VALUES ('myrkr.exe','MyrkrExe','myrkr.exe',$size,'$fv','1033',512,1)"
    $dllSize = (Get-Item $dllPath).Length
    Exec "INSERT INTO ``File`` (``File``,``Component_``,``FileName``,``FileSize``,``Version``,``Language``,``Attributes``,``Sequence``) VALUES ('myrkrshell.dll','$ShellComp','myrkrshell.dll',$dllSize,'$dllVer','1033',512,2)"
    Exec "INSERT INTO ``Media`` (``DiskId``,``LastSequence``,``DiskPrompt``,``Cabinet``,``VolumeLabel``,``Source``) VALUES (1,2,'','#myrkr.cab','','')"
    Exec "INSERT INTO ``Shortcut`` (``Shortcut``,``Directory_``,``Name``,``Component_``,``Target``,``Arguments``,``Description``,``ShowCmd``,``WkDir``) VALUES ('MyrkrSC','ProgramMenuFolder','Myrkr','MyrkrExe','[INSTALLDIR]myrkr.exe','','Myrkr file encryption',1,'INSTALLDIR')"

    # Upgrade: replace an existing install rather than sitting beside it.
    # Attributes is a bitfield whose Inclusive bits are NOT 1 and 2:
    #     0x001 MigrateFeatures   0x100 VersionMinInclusive
    #     0x002 OnlyDetect        0x200 VersionMaxInclusive
    # 768 = both Inclusive bits: replace anything from 0.0.0 up to and INCLUDING
    # this version.  Leaving VersionMax exclusive looks correct (every lower
    # version is replaced) but installing 1.0.0 over an existing 1.0.0 detects
    # nothing and registers a SECOND product - and every build gets a fresh
    # ProductCode, so any test of the same version hits it.  FindRelatedProducts
    # always skips our own ProductCode, so "including this version" can only match
    # a different build of it.
    $UPG_ATTR = 768
    Exec "INSERT INTO ``Upgrade`` (``UpgradeCode``,``VersionMin``,``VersionMax``,``Language``,``Attributes``,``Remove``,``ActionProperty``) VALUES ('$UpgradeCode','0.0.0','$productVersion','',$UPG_ATTR,'','OLDERVERSIONBEINGUPGRADED')"

    # Actions that establish properties for later actions run in the CLIENT
    # process.  Once the client's sequence finishes the installer marks them done,
    # so an action missing from InstallUISequence is skipped server-side as
    # "already done on client side" and never runs anywhere.
    $clientSide = @(
        @("LaunchConditions",      "",  100),
        @("FindRelatedProducts",   "",  200)
    )
    $seq = $clientSide + @(
        @("CostInitialize",        "",  800),
        @("FileCost",              "",  900),
        @("CostFinalize",          "", 1000),
        @("InstallValidate",       "", 1400),
        @("InstallInitialize",     "", 1500),
        # RemoveExistingProducts EARLY - immediately after InstallInitialize, one
        # of the five positions Windows Installer accepts (anywhere else is a
        # hard error 2613 at install time).
        #
        # It used to sit after InstallFinalize, on the reasoning that the new
        # build should be fully installed before the old one is removed so a
        # failure never leaves the user without an exe.  That is a real property,
        # and it cost the thing it was protecting: MSI only overwrites a VERSIONED
        # file when the incoming version is higher, myrkr.rc pins 1,0,0,0
        # permanently, so an upgrade logged
        #     "Won't Overwrite; Existing file is of an equal version"
        # and kept the old binary while reporting success.  A security fix shipped
        # that way would silently not land - verified against a real install.
        #
        # Removing the old product first means the file is gone before
        # InstallFiles runs, so the new one always installs.  The failure case is
        # covered by rollback, which is enabled by default: an install that dies
        # part-way restores the previous product rather than leaving nothing.
        @("RemoveExistingProducts","", 1550),
        @("ProcessComponents",     "", 1600),
        @("UnpublishFeatures",     "", 1800),
        # Policy values are put back by WriteRegistryValues on every install, so
        # removing them first is what makes a re-run with different properties
        # change the machine instead of merging into the old state.
        @("RemoveRegistryValues",  "", 2600),
        @("RemoveShortcuts",       "", 3200),
        @("RemoveFiles",           "", 3500),
        @("InstallFiles",          "", 4000),
        @("CreateShortcuts",       "", 4500),
        @("WriteRegistryValues",   "", 5000),
        @("RegisterUser",          "", 6000),
        @("RegisterProduct",       "", 6100),
        @("PublishFeatures",       "", 6300),
        @("PublishProduct",        "", 6400),
        @("InstallFinalize",       "", 6600)
    )
    # There is no shell-restart guard here any more, and there must not be one.
    # The version that was: an immediate custom action in InstallExecuteSequence
    # running `tasklist ... || start explorer.exe`.  It could not have worked.
    # Immediate actions in the EXECUTE sequence run in the SERVER process, which
    # for a per-machine install is SYSTEM in session 0 - so it would have started
    # explorer.exe in a session nobody can see, and its own tasklist check would
    # then have found that process and reported the shell healthy.  It failed
    # silently in exactly the case it was written for.
    #
    # Launching a shell into an interactive session is not something an elevated
    # installer should be doing at all.  Not shutting the shell down in the first
    # place is the fix; see MSIRESTARTMANAGERCONTROL above.

    foreach ($s in $seq) {
        Exec ("INSERT INTO ``InstallExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','{1}',{2})" -f $s[0], $s[1], $s[2])
    }
    # ,@(...) - without the leading comma ForEach-Object unrolls each pair into
    # the pipeline and the list becomes a flat run of strings.
    $uiSeq = @($clientSide | ForEach-Object { ,@($_[0], $_[2]) }) +
             @(@("CostInitialize",800),@("FileCost",900),@("CostFinalize",1000),@("ExecuteAction",1300))
    foreach ($a in $uiSeq) {
        Exec ("INSERT INTO ``InstallUISequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','',{1})" -f $a[0], $a[1])
    }
    foreach ($a in @(@("CostInitialize",800),@("FileCost",900),@("CostFinalize",1000),@("InstallValidate",1400),@("InstallInitialize",1500),@("InstallAdminPackage",3900),@("InstallFiles",4000),@("InstallFinalize",6600))) {
        Exec ("INSERT INTO ``AdminExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('{0}','',{1})" -f $a[0], $a[1])
    }

    # --- self-checks: every one of these is a SILENT failure in the field -----
    $ordered = $seq | Sort-Object { $_[2] }
    $names   = @($ordered | ForEach-Object { $_[0] })
    $idx     = [array]::IndexOf($names, "RemoveExistingProducts")
    $anchors = @("InstallValidate","InstallInitialize","InstallExecute","InstallExecuteAgain","InstallFinalize")
    if ($idx -lt 1) { throw "RemoveExistingProducts is missing from InstallExecuteSequence" }
    $prev = $names[$idx-1]
    if ($anchors -notcontains $prev) {
        $fmt = "RemoveExistingProducts follows '{0}' - Windows Installer only accepts it immediately after {1}. A real install would fail with error 2613."
        throw ($fmt -f $prev, ($anchors -join ", "))
    }
    Write-Host ("  sequence check : RemoveExistingProducts follows {0} - legal" -f $prev)

    $secure = $props["SecureCustomProperties"] -split ";"
    foreach ($p in $Policies) {
        if ($secure -notcontains $p.Prop) {
            throw ("{0} is missing from SecureCustomProperties - it would be dropped on the way to the elevated half of the install and silently do nothing" -f $p.Prop)
        }
        if ($p.Prop -cne $p.Prop.ToUpper()) {
            throw ("{0} is not all-uppercase, so MSI treats it as private and the command line cannot set it" -f $p.Prop)
        }
    }
    foreach ($o in @($AssocProp, $CtxProp, $ShellProp)) {
        if ($secure -notcontains $o) { throw "$o is missing from SecureCustomProperties - the opt-out would be ignored" }
    }
    if ($secure -notcontains $SdProp) { throw "$SdProp is missing from SecureCustomProperties - the secure-desktop opt-out would be ignored" }
    if ($props[$SdProp] -ne "1") { throw "$SdProp must default to 1, or an install that names nothing would disable the private desktop" }
    foreach ($d in $Defaults) {
        if ($secure -notcontains $d.Prop) {
            throw ("{0} is missing from SecureCustomProperties - it would be dropped on the way to the elevated half of the install and silently do nothing" -f $d.Prop)
        }
        if ($d.Prop -cne $d.Prop.ToUpper()) {
            throw ("{0} is not all-uppercase, so MSI treats it as private and the command line cannot set it" -f $d.Prop)
        }
    }
    $allGuids = @($ComponentGuid, $AssocGuid, $CtxGuid, $ShellGuid, $SdGuid) + ($Policies | ForEach-Object { $_.Guid }) + ($Defaults | ForEach-Object { $_.Guid })
    $dupGuid = $allGuids | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dupGuid) { throw ("component GUID reused: " + $dupGuid[0].Name) }
    foreach ($g in $allGuids) {
        if ($g -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') {
            throw "not a well-formed component GUID: $g"
        }
    }
    $allComps = @("MyrkrExe", $AssocComp, $CtxComp, $ShellComp, $SdComp) + ($Policies | ForEach-Object { $_.Comp }) + ($Defaults | ForEach-Object { $_.Comp })
    $dupComp = $allComps | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dupComp) { throw ("component name reused: " + $dupComp[0].Name) }
    # The CLSID the MSI registers and the one the DLL answers for live in two
    # files with nothing linking them; a mismatch registers a class no server
    # implements, and the menu item simply never appears.  Reassemble it from the
    # ASM's BYTES rather than matching the comment above them - a comment that has
    # drifted from its own data is exactly the failure this needs to catch.
    $asmPath = Join-Path (Split-Path $PSScriptRoot -Parent) "src\shellext.asm"
    $asm = Get-Content $asmPath -Raw
    $m = [regex]::Match($asm,
        'CLSID_MyrkrDrop\s+dd\s+0([0-9A-Fa-f]{8})h\s*(?:;[^\r\n]*)?[\r\n]+\s*' +
        'dw\s+0([0-9A-Fa-f]{4})h\s*,\s*0([0-9A-Fa-f]{4})h\s*[\r\n]+\s*' +
        'db\s+((?:0[0-9A-Fa-f]{2}h\s*,?\s*){8})')
    if (-not $m.Success) {
        throw "could not read CLSID_MyrkrDrop's bytes out of $asmPath - the definition changed shape, so this check no longer proves anything"
    }
    $d4 = [regex]::Matches($m.Groups[4].Value, '0([0-9A-Fa-f]{2})h') |
          ForEach-Object { $_.Groups[1].Value }
    $asmGuid = ("{{{0}-{1}-{2}-{3}{4}-{5}{6}{7}{8}{9}{10}}}" -f
                $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value,
                $d4[0], $d4[1], $d4[2], $d4[3], $d4[4], $d4[5], $d4[6], $d4[7])
    if ($asmGuid.ToUpper() -ne $DropClsid.ToUpper()) {
        throw "src\shellext.asm defines CLSID $asmGuid but the MSI registers $DropClsid - the MSI would register a class the DLL does not answer for"
    }
    Write-Host ("  clsid check    : {0} matches src\shellext.asm" -f $asmGuid)
    foreach ($a in @("WriteRegistryValues","RemoveRegistryValues")) {
        if ($names -notcontains $a) { throw "$a is missing - the Registry table would never be processed" }
    }
    Write-Host ("  policy check   : {0} properties secure, unique and sequenced" -f $Policies.Count)

    $uiNames = @($uiSeq | ForEach-Object { $_[0] })
    foreach ($a in $clientSide) {
        if ($uiNames -notcontains $a[0]) {
            throw ("{0} is in InstallExecuteSequence but not InstallUISequence - the server would skip it as 'already done on client side' and it would never run at all" -f $a[0])
        }
    }
    Write-Host ("  client-side    : {0} present in both sequences" -f (($clientSide | ForEach-Object { $_[0] }) -join ", "))

    if (-not ($UPG_ATTR -band 512)) {
        throw "Upgrade.Attributes lacks VersionMaxInclusive (0x200) - a rebuild of $productVersion would install ALONGSIDE the existing one instead of replacing it"
    }
    Write-Host ("  upgrade check  : replaces 0.0.0 .. {0} inclusive" -f $productVersion)

    # --- summary information (required, and x64 must be declared) ------------
    $si = $db.SummaryInformation(20)
    function SetSI([int]$id, $val) {
        $si.GetType().InvokeMember("Property","SetProperty",$null,$si,@($id,$val))
    }
    SetSI 1  1252
    SetSI 2  "Myrkr"
    SetSI 3  "Myrkr file encryption"
    SetSI 4  $Manufacturer
    SetSI 5  "Installer,MSI,Database"
    SetSI 6  "Per-machine install of Myrkr $productVersion"
    SetSI 7  "x64;1033"                             # template: 64-bit package
    SetSI 9  ("{" + [guid]::NewGuid().ToString().ToUpper() + "}")
    # Summary property 14 is the MINIMUM Windows Installer version the package
    # requires.  It was 200 (Installer 2.0), which silently opted the package out
    # of Restart Manager: RM integration arrived in Installer 4.0, and a package
    # declaring 2.0 gets the legacy in-use handling instead - rename the locked
    # file, drop the new one beside it, carry on.
    #
    # For an ordinary exe that is fine.  For a SHELL EXTENSION it is not: Explorer
    # keeps myrkrshell.dll mapped between uses, so the rename leaves a running
    # Explorer executing the OLD code against the NEW registry entries until it is
    # restarted.  That mismatch is the leading suspect for the explorer.exe hangs
    # that followed an upgrade (see the parked feature/ctx-menu-handler branch).
    #
    # 400 lets the installer use Restart Manager, which detects that explorer.exe
    # holds the file and can shut it down and restart it as part of the
    # transaction.  Windows 11 is far above this floor, so the raised requirement
    # costs nothing.
    #
    # UNVERIFIED: that RM actually closes and restarts Explorer here has NOT been
    # confirmed on a live install - it needs an elevated `msiexec /i ... /l*v` and
    # a look for the RESTART MANAGER block in the log.  Do not treat this as fixed
    # until that log exists.
    SetSI 14 400
    SetSI 15 2                                      # source is compressed
    $si.Persist()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($si)

    $db.Commit()

    # --- embed the cab as a stream -------------------------------------------
    # _Streams is an implicit MSI table - it always exists and CREATE TABLE on it
    # fails.  Insert straight into it.
    $view = $db.OpenView("INSERT INTO ``_Streams`` (``Name``,``Data``) VALUES ('myrkr.cab', ?)")
    $rec  = $installer.CreateRecord(1)
    $rec.SetStream(1, $cab)
    $view.Execute($rec)
    $view.Close()
    $db.Commit()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($rec)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
    # the database keeps the .msi open until the COM objects are actually gone
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()

    Write-Host ""
    Write-Host ("  MSI            : {0}" -f $outMsi)
    Write-Host ("  size           : {0} bytes" -f (Get-Item $outMsi).Length)
    Write-Host ("  ProductCode    : {0}" -f $productCode)
    Write-Host ("  UpgradeCode    : {0}  (never change this)" -f $UpgradeCode)
    Write-Host ""
    Write-Host "  installs   %ProgramFiles%\$InstallDir\{myrkr.exe, myrkrshell.dll} + an all-users Start Menu shortcut"
    Write-Host "  scope      per-machine: elevation required, binary read-only to standard users"
    Write-Host "  owns       that file, the shortcut, and any policy value named below"
    Write-Host "  uninstall  removes exactly those; containers and HKCU settings are untouched"
    Write-Host ""
    Write-Host ("  HKLM\{0}  - set only what you name; an unnamed value is not written," -f $PolicyKey)
    Write-Host "  and in Myrkr a value's PRESENCE is what locks it against the user."
    Write-Host ""
    Write-Host ("    {0,-20} {1,-12} {2,-8} {3}" -f "PROPERTY", "VALUE", "RANGE", "MEANING (default)")
    foreach ($p in $Policies) {
        Write-Host ("    {0,-20} {1,-12} {2,-8} {3} ({4})" -f $p.Prop, $p.Value, $p.Range, $p.Doc, $p.Default)
    }
    Write-Host ("    {0,-20} {1,-12} {2,-8} {3}" -f $SdProp, $SdValue, "0/1", "type the password on a private desktop (1)")
    Write-Host ""
    Write-Host "  $SdValue is the exception to the rule above: it is written whether or not"
    Write-Host "  you name it, because a control a user can switch off is not a control. It"
    Write-Host "  is what stops the prompt being found and driven by another process, so the"
    Write-Host "  default install locks it ON. $SdProp=0 allows the ordinary prompt"
    Write-Host "  - see manifest 14.6 for what that costs before you use it."
    Write-Host ""
    Write-Host ("  HKLM\{0}  - the same settings as a STARTING" -f $DefaultsKey)
    Write-Host "  value instead of a locked one. Myrkr reads these first, then the user's own"
    Write-Host "  HKCU settings on top, so a deployed default is what a new user gets and any"
    Write-Host "  change they make sticks. Name both keys and the policy one wins."
    Write-Host ""
    Write-Host ("    {0,-24} {1,-14} {2}" -f "PROPERTY", "VALUE", "MEANING")
    foreach ($d in $Defaults) {
        Write-Host ("    {0,-24} {1,-14} {2}" -f $d.Prop, $d.Value, $d.Doc)
    }
    Write-Host ""
    Write-Host "  HKLM rather than HKCU: a per-machine MSI writing HKCU reaches only the"
    Write-Host "  account that ran msiexec, so every other user on the box would get nothing."
    Write-Host ""
    Write-Host "    msiexec /i `"$outMsi`" /qn MYRKR_MINLEN=16 MYRKR_LOGLEVEL=3"
    Write-Host "    msiexec /i `"$outMsi`" /qn MYRKR_DEF_FORMAT=1        (Zip by default, not locked)"
    Write-Host ""
    Write-Host "  MSI does not remember properties: repeat them on upgrades too, or the"
    Write-Host "  old product's policy values are removed along with it."
    Write-Host ""
    Write-Host ("  .mrk          -> {0}, opened by [INSTALLDIR]myrkr.exe  ({1}=1 to skip)" -f $ProgId, $AssocProp)
    Write-Host ("  shell ext     -> myrkrshell.dll, registered as {0}" -f $DropClsid)
    Write-Host ("                   right-CLICK a selection (files or folders):")
    Write-Host ("                     'Myrkr encrypt' / 'Myrkr decrypt' / 'Myrkr extract'")
    Write-Host ("                   right-DRAG a selection onto a folder or drive:")
    Write-Host ("                     the same, and the output goes where you dropped it")
    Write-Host ("                   Either way the WHOLE selection goes to ONE window.")
    Write-Host ("                   ({0}=1 skips the right-click handler;" -f $CtxProp)
    Write-Host ("                    {0}=1 installs neither the DLL nor any of it)" -f $ShellProp)
    Write-Host ""
    Write-Host "  This DLL is loaded INTO explorer.exe, which is the one thing here that runs"
    Write-Host "  in a process Myrkr does not own. It launches myrkr.exe and does nothing else:"
    Write-Host "  no crypto and no password handling happen inside Explorer. Uninstall may need"
    Write-Host "  a restart if Explorer still has it loaded - Windows Installer will say so."
}
finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}
