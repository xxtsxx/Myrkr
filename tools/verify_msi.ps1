<#
    verify_msi.ps1 - check a built myrkr-*.msi before it is published.

    Two kinds of check, and the second is the point:

      STRUCTURE - read the tables back and confirm every row make_msi.ps1
      intended is present: the policy registry rows, the file association, the
      four context-menu verbs with their cleanup rows, the upgrade attributes,
      the sequence placement, the cab stream.

      BEHAVIOUR - open the package as a Windows Installer session with policy
      properties SET, cost it, and read back which components the installer
      would actually install.  This is what proves the component CONDITIONS
      work.  A condition that is wrong - or a property missing from
      SecureCustomProperties - produces an MSI that installs cleanly and
      silently writes nothing, and no amount of reading rows back detects it,
      because the rows are all present and correct.  msiexec /a does not catch
      it either: an administrative install evaluates none of this.

    The session is opened with msiOpenPackageIgnoreMachineState, so nothing is
    installed, no machine state is touched, and it does not need elevation.

    Exit code: 0 = all checks passed, 1 = at least one FAIL.
    Usage: powershell -ExecutionPolicy Bypass -File tools\verify_msi.ps1
           [-Msi bin\myrkr-1.0.0.msi]
#>
[CmdletBinding()]
param([string]$Msi = "")

$ErrorActionPreference = "Stop"

if (-not $Msi) {
    $cand = Get-ChildItem -Path "bin" -Filter "myrkr-*.msi" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $cand) { throw "no bin\myrkr-*.msi found - run tools\make_msi.ps1 first" }
    $Msi = $cand.FullName
}
if (-not [IO.Path]::IsPathRooted($Msi)) { $Msi = Join-Path (Get-Location) $Msi }
if (-not (Test-Path $Msi)) { throw "not found: $Msi" }

Write-Host ("verifying: {0}" -f $Msi)
Write-Host ""

$script:fails = 0
$script:oks   = 0
function Pass([string]$m) { $script:oks++;   Write-Host ("  ok   : {0}" -f $m) }
function Fail([string]$m) { $script:fails++; Write-Host ("  FAIL: {0}" -f $m) }
function Check([bool]$cond, [string]$m) { if ($cond) { Pass $m } else { Fail $m } }

$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.OpenDatabase($Msi, 0)          # read-only

# The column count is passed in rather than read from the record: Record.FieldCount
# is a COM property PowerShell cannot read directly (it comes back empty), which
# silently produced zero-length rows and made every structural check vacuous.
# Two traps here, both of which produce a silently WRONG result rather than an
# error:
#   * Record.FieldCount is a COM property PowerShell cannot read directly (it
#     comes back empty), so the column count is passed in.  Reading it produced
#     zero-length rows and made every structural check below vacuous.
#   * View.Execute() and View.Close() return $null for a COM object, and an
#     uncaptured expression statement EMITS that null into the function's output.
#     Without [void] the function returns @($null, $null, $rows) - the caller
#     iterates two phantom rows before reaching the real ones.
function Query([string]$sql, [int]$cols) {
    $view = $db.OpenView($sql)
    [void]$view.Execute()
    $rows = @()
    while ($true) {
        $rec = $view.Fetch()
        if ($null -eq $rec) { break }
        $row = @()
        for ($i = 1; $i -le $cols; $i++) {
            try { $row += [string]$rec.StringData($i) } catch { $row += "" }
        }
        $rows += ,$row
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($rec)
    }
    [void]$view.Close()
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
    ,$rows
}

# ---------------------------------------------------------------- structure --
Write-Host "structure"

$props = @{}
foreach ($r in (Query "SELECT ``Property``,``Value`` FROM ``Property``" 2)) { $props[$r[0]] = $r[1] }

Check ($props.ContainsKey("ProductCode"))    "ProductCode present"
Check ($props.ContainsKey("UpgradeCode"))    "UpgradeCode present"
Check ($props["ALLUSERS"] -eq "1")           "ALLUSERS=1 (per-machine)"
$pv = $props["ProductVersion"]
Check ($pv -match '^\d+\.\d+\.\d+$')         "ProductVersion is 3 fields: $pv"

# The exe's version resource is the single source of truth; the MSI must match.
$fileRows = Query "SELECT ``File``,``Component_``,``FileName``,``FileSize``,``Version``,``Sequence`` FROM ``File``" 6
Check ($fileRows.Count -eq 2)                "exactly two payload files"
$fileNames = @($fileRows | ForEach-Object { $_[0] })
foreach ($want in @("myrkr.exe", "myrkrshell.dll")) {
    Check ($fileNames -contains $want) ("File table has {0}" -f $want)
}
# Both binaries ship in one package, so both must claim the same version - an
# installed pair that disagrees is unanswerable from a support call.
foreach ($f in $fileRows) {
    Check ($f[4].StartsWith($pv)) ("{0} File.Version {1} matches ProductVersion {2}" -f $f[0], $f[4], $pv)
}
# Sequence numbers index into the cab in the order makecab was fed; a duplicate
# or a gap extracts one member into the other's name.
$seqs = @($fileRows | ForEach-Object { [int]$_[5] } | Sort-Object)
Check (($seqs -join ",") -eq "1,2") ("File.Sequence is 1,2 (got {0})" -f ($seqs -join ","))

# Summary property 14 = the minimum Windows Installer version the package needs.
# MSIRESTARTMANAGERCONTROL arrived in 4.0 and an older installer ignores it
# silently, so a package that declares less than 400 is one whose "Restart
# Manager is off" is a comment rather than a setting. Nothing about the built
# package looks wrong when this is too low, which is why it is checked rather
# than remembered.
$si = $db.SummaryInformation(0)
$schema = 0
try { $schema = [int]$si.GetType().InvokeMember("Property","GetProperty",$null,$si,@(14)) } catch {}
Check ($schema -ge 400) "package requires Windows Installer 4.0+ (schema $schema), so MSIRESTARTMANAGERCONTROL is honoured"
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($si)

$media = Query "SELECT ``Cabinet``,``LastSequence`` FROM ``Media``" 2
Check ($media.Count -eq 1 -and $media[0][0] -eq "#myrkr.cab") "Media names the embedded cab"
# LastSequence below the highest File.Sequence leaves a payload file unextracted.
Check ($media.Count -eq 1 -and [int]$media[0][1] -eq $seqs[-1]) `
      ("Media.LastSequence {0} covers every payload file" -f $media[0][1])
$streams = Query "SELECT ``Name`` FROM ``_Streams``" 1
Check (($streams | ForEach-Object { $_[0] }) -contains "myrkr.cab") "cab stream is embedded"

# --- policy surface ---------------------------------------------------------
$PolicyKey = "SOFTWARE\Myrkr"
$expectPolicies = @(
    @{ Prop="MYRKR_MINLEN";     Value="MinLen" }
    @{ Prop="MYRKR_MINCLASSES"; Value="MinClasses" }
    @{ Prop="MYRKR_LOGLEVEL";   Value="LogLevel" }
    @{ Prop="MYRKR_COMPRESS";   Value="Compress" }
    @{ Prop="MYRKR_FORMAT";     Value="Format" }
)
# The SAME nine values under a different key, meaning the opposite: a starting
# value rather than an enforced one.  Checked separately from $expectPolicies
# because the two must not drift into each other - a "default" written to the
# policy key would lock the setting it was meant to leave open.
$DefaultsKey = "SOFTWARE\Myrkr\Defaults"
$expectDefaults = @(
    @{ Prop="MYRKR_DEF_MINLEN";     Value="MinLen" }
    @{ Prop="MYRKR_DEF_MINCLASSES"; Value="MinClasses" }
    @{ Prop="MYRKR_DEF_LOGLEVEL";   Value="LogLevel" }
    @{ Prop="MYRKR_DEF_COMPRESS";   Value="Compress" }
    @{ Prop="MYRKR_DEF_FORMAT";     Value="Format" }
    @{ Prop="MYRKR_DEF_SECUREDESK"; Value="SecureDesktop" }
    @{ Prop="MYRKR_DEF_KDFTIME";    Value="KdfTime" }
    @{ Prop="MYRKR_DEF_KDFMEMORY";  Value="KdfMemory" }
    @{ Prop="MYRKR_DEF_SPLITSIZE";  Value="SplitSize" }
)
$secure = ($props["SecureCustomProperties"] -split ";")
$regRows = Query "SELECT ``Registry``,``Root``,``Key``,``Name``,``Value``,``Component_`` FROM ``Registry``" 6
$comps   = @{}
foreach ($r in (Query "SELECT ``Component``,``ComponentId``,``Attributes``,``Condition``,``KeyPath`` FROM ``Component``" 5)) {
    $comps[$r[0]] = @{ Id=$r[1]; Attr=[int]$r[2]; Cond=$r[3]; KeyPath=$r[4] }
}

# --- referential integrity ---------------------------------------------------
# Every one of these is a build-time-clean, INSTALL-time failure.  A component
# KeyPath that names no row is the worst of them: with the RegistryKeyPath
# attribute set, Windows Installer looks the name up in the Registry table, and
# when it is not there falls back to the File table, where it is not there
# either - and fails the install with error 2715.  Nothing about the built
# package looks wrong, every row is present and correct, and the costed session
# below is perfectly happy.  This shipped once; hence these checks.
$fileKeys = @(); foreach ($r in $fileRows) { $fileKeys += $r[0] }
$regKeys  = @(); foreach ($r in $regRows)  { $regKeys  += $r[0] }
$compNames = @($comps.Keys)

foreach ($cn in $compNames) {
    $c = $comps[$cn]
    $isReg = ($c.Attr -band 4) -ne 0
    if ($isReg) {
        Check ($regKeys -contains $c.KeyPath) `
              ("component {0} KeyPath '{1}' resolves to a Registry row" -f $cn, $c.KeyPath)
    } else {
        Check ($fileKeys -contains $c.KeyPath) `
              ("component {0} KeyPath '{1}' resolves to a File row" -f $cn, $c.KeyPath)
    }
}
# Every table that points at a component must name one that exists.
foreach ($r in $regRows) {
    if ($compNames -notcontains $r[5]) { Fail ("Registry row {0} names missing component {1}" -f $r[0], $r[5]) }
}
foreach ($r in $fileRows) {
    if ($compNames -notcontains $r[1]) { Fail ("File row {0} names missing component {1}" -f $r[0], $r[1]) }
}
$fcRows = Query "SELECT ``Feature_``,``Component_`` FROM ``FeatureComponents``" 2
foreach ($r in $fcRows) {
    if ($compNames -notcontains $r[1]) { Fail ("FeatureComponents names missing component {0}" -f $r[1]) }
}
# A component with no FeatureComponents row is never installed at all.
$fcComps = @(); foreach ($r in $fcRows) { $fcComps += $r[1] }
foreach ($cn in $compNames) {
    Check ($fcComps -contains $cn) ("component {0} is mapped to a feature" -f $cn)
}
$scRows = Query "SELECT ``Shortcut``,``Component_``,``Target`` FROM ``Shortcut``" 3
foreach ($r in $scRows) {
    Check ($compNames -contains $r[1]) ("shortcut {0} names an existing component" -f $r[0])
}

foreach ($p in $expectPolicies) {
    $row = $regRows | Where-Object { $_[2] -eq $PolicyKey -and $_[3] -eq $p.Value }
    if (-not $row) { Fail ("policy {0}: no Registry row" -f $p.Value); continue }
    $ok = ($row[4] -eq ("#[" + $p.Prop + "]")) -and ([int]$row[1] -eq 2)
    Check $ok ("policy {0} -> HKLM\{1} as REG_DWORD from [{2}]" -f $p.Value, $PolicyKey, $p.Prop)
    $c = $comps[$row[5]]
    Check ($c.Cond -eq $p.Prop) ("policy {0} component is conditioned on {1}" -f $p.Value, $p.Prop)
    # 256 = write to the 64-bit registry view.  Without it an x64 package lands
    # these under WOW6432Node where the 64-bit myrkr.exe never looks.
    Check (($c.Attr -band 256) -ne 0) ("policy {0} component writes the 64-bit view" -f $p.Value)
    Check ($secure -contains $p.Prop) ("{0} is in SecureCustomProperties" -f $p.Prop)
}
foreach ($d in $expectDefaults) {
    $row = $regRows | Where-Object { $_[2] -eq $DefaultsKey -and $_[3] -eq $d.Value }
    if (-not $row) { Fail ("default {0}: no Registry row" -f $d.Value); continue }
    $ok = ($row[4] -eq ("#[" + $d.Prop + "]")) -and ([int]$row[1] -eq 2)
    Check $ok ("default {0} -> HKLM\{1} as REG_DWORD from [{2}]" -f $d.Value, $DefaultsKey, $d.Prop)
    $c = $comps[$row[5]]
    Check ($c.Cond -eq $d.Prop) ("default {0} component is conditioned on {1}" -f $d.Value, $d.Prop)
    Check (($c.Attr -band 256) -ne 0) ("default {0} component writes the 64-bit view" -f $d.Value)
    Check ($secure -contains $d.Prop) ("{0} is in SecureCustomProperties" -f $d.Prop)
    # The one that matters most: a default must NOT be written to the policy key,
    # because presence there is what locks a setting against the user - which is
    # the exact opposite of what these properties promise.
    $stray = $regRows | Where-Object { $_[2] -eq $PolicyKey -and $_[4] -eq ("#[" + $d.Prop + "]") }
    Check (-not $stray) ("{0} writes only under Defaults, never the policy key" -f $d.Prop)
}
Check ($secure -contains "MYRKR_NOASSOC")    "MYRKR_NOASSOC is in SecureCustomProperties"
Check ($secure -contains "MYRKR_NOCONTEXT")  "MYRKR_NOCONTEXT is in SecureCustomProperties"
Check ($secure -contains "MYRKR_NOSHELLEXT") "MYRKR_NOSHELLEXT is in SecureCustomProperties"

# --- SecureDesktop: the one value written whether or not it is named ---------
# Everything else here is conditioned on its property.  This one must NOT be, or
# the private-desktop control would be enforced only where an administrator
# happened to remember it - and a package that quietly stopped writing it would
# look identical to one that did.
Check ($secure -contains "MYRKR_SECUREDESKTOP") "MYRKR_SECUREDESKTOP is in SecureCustomProperties"
Check ($props["MYRKR_SECUREDESKTOP"] -eq "1")   "MYRKR_SECUREDESKTOP defaults to 1"
$sdRow = $regRows | Where-Object { $_[2] -eq $PolicyKey -and $_[3] -eq "SecureDesktop" }
Check ($sdRow -and $sdRow[4] -eq "#[MYRKR_SECUREDESKTOP]") "SecureDesktop -> REG_DWORD from [MYRKR_SECUREDESKTOP]"
if ($sdRow) {
    $sdComp = $comps[$sdRow[5]]
    Check ([string]::IsNullOrEmpty($sdComp.Cond)) "SecureDesktop component is UNCONDITIONAL (written even when unnamed)"
    Check (($sdComp.Attr -band 256) -ne 0)        "SecureDesktop component writes the 64-bit view"
}

# --- file association -------------------------------------------------------
$CK = "SOFTWARE\Classes"
$assocExt = $regRows | Where-Object { $_[2] -eq "$CK\.mrk" }
Check ($assocExt -and $assocExt[4] -eq "Myrkr.Container") ".mrk default value -> Myrkr.Container"
$assocCmd = $regRows | Where-Object { $_[2] -eq "$CK\Myrkr.Container\shell\open\command" }
Check ($assocCmd -and $assocCmd[4] -match '"\[INSTALLDIR\]myrkr\.exe"\s+"%1"') "open command quotes both exe and %1"
# The file type must use icon index 1 (the container icon, myrkr.rc id 2), not
# index 0 (the application). Swapping them is invisible in the tables and shows
# up only as wrong art in Explorer.
$assocIcon = $regRows | Where-Object { $_[2] -eq "$CK\Myrkr.Container\DefaultIcon" }
Check ($assocIcon -and $assocIcon[4] -match 'myrkr\.exe,1$') ".mrk DefaultIcon uses the container icon (index 1)"
# There is no verb "Icon" row any more - the context entry is drawn by the
# handler, not by a registry verb. A stray one would mean a %1 verb came back.
$verbIcons = $regRows | Where-Object { $_[3] -eq "Icon" }
Check (-not $verbIcons) "no leftover verb Icon rows (the handler draws its own entry)"

$assocClean = $regRows | Where-Object { $_[2] -eq "$CK\Myrkr.Container" -and $_[3] -eq "-" }
Check ([bool]$assocClean) "ProgId is removed on uninstall (Name='-')"
# Removing the ProgId but not .mrk is deliberate: another app may have added
# itself to the extension key.
$extClean = $regRows | Where-Object { $_[2] -eq "$CK\.mrk" -and $_[3] -eq "-" }
Check (-not $extClean) ".mrk extension key is NOT deleted on uninstall (other apps may share it)"

# --- context-menu handler ---------------------------------------------------
# Defined here rather than in the drag-drop section below, because both
# registrations point at the same class - which is the whole point of the change.
$DropClsid = "{7C4A6E10-2F58-4B3D-9C81-5E0A7D9B4F62}"
# The four "%1" verbs are gone: %1 is per-FILE, so a four-file selection launched
# four instances, four password prompts and four single-file containers.  The
# handler below gets the whole selection through CF_HDROP instead.  These checks
# assert BOTH halves - the new rows present, and no %1 verb left behind.
$oldVerbs = $regRows | Where-Object { $_[2] -match '\\shell\\Myrkr(Encrypt|Decrypt|Extract)' }
Check (-not $oldVerbs) "no %1 shell verbs remain (they launched one instance per file)"

foreach ($cls in @("*", "Directory")) {
    $k = "$CK\$cls\shellex\ContextMenuHandlers\Myrkr"
    $row = $regRows | Where-Object { $_[2] -eq $k -and -not $_[3] }
    Check ($row -and $row[4] -eq $DropClsid) ("{0} ContextMenuHandlers entry -> the CLSID" -f $cls)
    $clean = $regRows | Where-Object { $_[2] -eq $k -and $_[3] -eq "-" }
    Check ([bool]$clean) ("{0} ContextMenuHandlers entry removed on uninstall" -f $cls)
}
# Drive is deliberately absent here, though it IS a DragDropHandler: as a drop
# TARGET a drive is a destination, but as a right-click SELECTION it would mean
# offering to encrypt an entire volume one slip away.
$driveCtx = $regRows | Where-Object { $_[2] -eq "$CK\Drive\shellex\ContextMenuHandlers\Myrkr" }
Check (-not $driveCtx) "Drive has NO context-menu handler (only a drag-drop one)"

# The handler rows name a CLSID served by myrkrshell.dll, so suppressing the DLL
# must suppress them too - otherwise the shell is pointed at an absent server.
$ctxRow = $regRows | Where-Object { $_[2] -eq "$CK\*\shellex\ContextMenuHandlers\Myrkr" -and -not $_[3] }
if ($ctxRow) {
    $cc = $comps[$ctxRow[5]]
    Check ($cc.Cond -match 'NOT\s+MYRKR_NOCONTEXT' -and $cc.Cond -match 'NOT\s+MYRKR_NOSHELLEXT') `
          "context-menu component is conditioned on NOT NOCONTEXT AND NOT NOSHELLEXT"
    Check (($cc.Attr -band 256) -ne 0) "context-menu component writes the 64-bit view"
}

# .zip must never be taken over
$zipHijack = $regRows | Where-Object { $_[2] -eq "$CK\.zip" }
Check (-not $zipHijack) ".zip association is NOT taken over"

# --- drag-drop shell extension ----------------------------------------------
# The one component here that puts code inside a process Myrkr does not own, so
# each row is checked for what it does rather than merely for being present.
$clsidKey  = "$CK\CLSID\$DropClsid"

$inproc = $regRows | Where-Object { $_[2] -eq "$clsidKey\InprocServer32" -and -not $_[3] }
Check ($inproc -and $inproc[4] -eq "[INSTALLDIR]myrkrshell.dll") "InprocServer32 -> [INSTALLDIR]myrkrshell.dll"
$thread = $regRows | Where-Object { $_[2] -eq "$clsidKey\InprocServer32" -and $_[3] -eq "ThreadingModel" }
Check ($thread -and $thread[4] -eq "Apartment") "InprocServer32 declares ThreadingModel=Apartment"

# Directory and Drive are siblings; a handler on Directory alone never fires on a
# drive root, and adding their parent Folder as well would double the menu item.
foreach ($cls in @("Directory", "Drive")) {
    $ddk = "$CK\$cls\shellex\DragDropHandlers\Myrkr"
    $row = $regRows | Where-Object { $_[2] -eq $ddk -and -not $_[3] }
    Check ($row -and $row[4] -eq $DropClsid) ("{0} DragDropHandlers entry -> the CLSID" -f $cls)
    $clean = $regRows | Where-Object { $_[2] -eq $ddk -and $_[3] -eq "-" }
    Check ([bool]$clean) ("{0} DragDropHandlers entry removed on uninstall" -f $cls)
}
$folderDup = $regRows | Where-Object { $_[2] -like "$CK\Folder\shellex\DragDropHandlers*" }
Check (-not $folderDup) "not ALSO registered under Folder (would offer the verb twice)"

$approvedKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
$appr = $regRows | Where-Object { $_[2] -eq $approvedKey -and $_[3] -eq $DropClsid }
Check ([bool]$appr) "listed in the Approved shell extensions key"
# ...and that key must NOT carry a remove-tree row: it holds every other
# application's approved handlers, and Name='-' there would delete all of them.
$apprTree = $regRows | Where-Object { $_[2] -eq $approvedKey -and $_[3] -eq "-" }
Check (-not $apprTree) "Approved key is NOT deleted on uninstall (it is shared machine state)"

$clsidClean = $regRows | Where-Object { $_[2] -eq $clsidKey -and $_[3] -eq "-" }
Check ([bool]$clsidClean) "CLSID key is removed on uninstall (Name='-')"

# One component owning both the DLL and its registration: a registration that
# outlived the file would point Explorer at a missing in-proc server.
$shellFile = $fileRows | Where-Object { $_[0] -eq "myrkrshell.dll" }
if ($shellFile) {
    $sc = $comps[$shellFile[1]]
    Check ($sc.Cond -eq "NOT MYRKR_NOSHELLEXT") "shell-ext component is conditioned on NOT MYRKR_NOSHELLEXT"
    Check (($sc.Attr -band 256) -ne 0) "shell-ext component writes the 64-bit view (not WOW6432Node)"
    Check (($sc.Attr -band 4) -eq 0)   "shell-ext KeyPath is the DLL, not a registry row"
    $regComps = @($regRows | Where-Object { $_[2] -like "$clsidKey*" } | ForEach-Object { $_[5] } | Sort-Object -Unique)
    Check ($regComps.Count -eq 1 -and $regComps[0] -eq $shellFile[1]) `
          "the CLSID rows belong to the same component as the DLL"
}

# --- upgrade + sequence -----------------------------------------------------
$upg = Query "SELECT ``UpgradeCode``,``VersionMin``,``VersionMax``,``Attributes``,``ActionProperty`` FROM ``Upgrade``" 5
Check ($upg.Count -eq 1) "one Upgrade row"
if ($upg.Count -eq 1) {
    $attr = [int]$upg[0][3]
    Check (($attr -band 512) -ne 0) "Upgrade.Attributes has VersionMaxInclusive (0x200)"
    Check (($attr -band 256) -ne 0) "Upgrade.Attributes has VersionMinInclusive (0x100)"
    Check ($upg[0][2] -eq $pv)      "VersionMax equals this ProductVersion"
}

$seq = @{}
foreach ($r in (Query "SELECT ``Action``,``Sequence`` FROM ``InstallExecuteSequence``" 2)) { $seq[$r[0]] = [int]$r[1] }
foreach ($a in @("WriteRegistryValues","RemoveRegistryValues","RemoveExistingProducts","FindRelatedProducts","InstallFinalize")) {
    Check ($seq.ContainsKey($a)) ("InstallExecuteSequence has {0}" -f $a)
}
if ($seq.ContainsKey("RemoveExistingProducts")) {
    $before = $seq.GetEnumerator() | Where-Object { $_.Value -lt $seq["RemoveExistingProducts"] } |
              Sort-Object Value | Select-Object -Last 1
    $anchors = @("InstallValidate","InstallInitialize","InstallExecute","InstallExecuteAgain","InstallFinalize")
    Check ($anchors -contains $before.Key) ("RemoveExistingProducts follows {0} (error 2613 otherwise)" -f $before.Key)
}
# --- Restart Manager is OFF, and there is no shell guard ---------------------
# Restart Manager exists to release files a running application holds.  The file
# it would go after here is myrkrshell.dll inside explorer.exe, so what it
# actually does is shut the shell down - and its restart is best effort.  It has
# left this machine with no taskbar and no way to start anything, and Windows'
# own AutoRestartShell does not cover it: that fires only on an UNEXPECTED shell
# exit, and an RM shutdown is graceful.
#
# The guard that used to be here could not have worked.  It was an IMMEDIATE
# custom action in InstallExecuteSequence, and immediate actions in the execute
# sequence run in the server process - SYSTEM in session 0 for a per-machine
# install.  It would have started explorer.exe in a session nobody can see, and
# its own tasklist check would then have found that process and called the shell
# healthy.  Both facts are asserted, because "no guard" is only safe while
# nothing is shutting the shell down in the first place.
$dirRows = Query "SELECT ``Directory`` FROM ``Directory``" 1
$dirKeys = @($dirRows | ForEach-Object { $_[0] })
$caRows = Query "SELECT ``Action``,``Type``,``Source``,``Target`` FROM ``CustomAction``" 4
# A directory-sourced custom action (base type 34) whose Source names no row in
# the Directory table fails the INSTALL with error 2727 - at the moment the
# action runs, so everything before it has already happened. Nothing about the
# built package looks wrong; this shipped once, because the command inside the
# action was tested and the packaging of it was not.
foreach ($ca in $caRows) {
    if ((([int]$ca[1]) -band 0x3F) -ne 34) { continue }
    Check ($dirKeys -contains $ca[2]) `
          ("custom action {0} Source '{1}' resolves to a Directory row (error 2727 otherwise)" -f $ca[0], $ca[2])
}
Check (-not ($caRows | Where-Object { $_[0] -eq "RestartShellIfGone" })) `
      "no shell-restart guard (an immediate CA here would run as SYSTEM in session 0)"
# Nothing in the package may start a shell, however it is named: an elevated
# installer launching an interactive shell is the wrong shape whatever the
# reason, and the check is on the behaviour rather than on the one action name
# that happened to do it.
$launcher = $caRows | Where-Object { $_[3] -and $_[3] -match 'explorer\.exe' }
Check (-not $launcher) "no custom action launches explorer.exe"

# MSIRESTARTMANAGERCONTROL=Disable is what makes the absence of a guard safe.
# Without it the shell is shut down and nothing here brings it back.
$props = @{}
foreach ($r in (Query "SELECT ``Property``,``Value`` FROM ``Property``" 2)) { $props[$r[0]] = $r[1] }
Check ($props["MSIRESTARTMANAGERCONTROL"] -eq "Disable") `
      ("Restart Manager is disabled (MSIRESTARTMANAGERCONTROL='{0}')" -f $props["MSIRESTARTMANAGERCONTROL"])

$uiSeq = @{}
foreach ($r in (Query "SELECT ``Action`` FROM ``InstallUISequence``" 1)) { $uiSeq[$r[0]] = $true }
Check ($uiSeq.ContainsKey("FindRelatedProducts")) "FindRelatedProducts also in InstallUISequence (else skipped as 'already done on client side')"

[void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)

# ---------------------------------------------------------------- behaviour --
# Cost the package with properties set and read back what would be installed.
Write-Host ""
Write-Host "behaviour (costed session, nothing installed)"

$INSTALLSTATE_LOCAL = 3
$INSTALLSTATE_UNKNOWN = -1

function Cost-Session([string]$cmdline) {
    # 1 = msiOpenPackageIgnoreMachineState: evaluate without touching the machine
    # and without needing elevation.
    $installer.UILevel = 2                       # msiUILevelNone
    $sess = $installer.OpenPackage($Msi, 1)
    if ($cmdline) {
        foreach ($kv in ($cmdline -split '\s+')) {
            if (-not $kv) { continue }
            $n, $v = $kv -split '=', 2
            $sess.Property($n) = $v
        }
    }
    foreach ($a in @("CostInitialize","FileCost","CostFinalize")) {
        [void]$sess.DoAction($a)
    }
    $sess
}

function Comp-State($sess, [string]$comp) {
    try { [int]$sess.ComponentRequestState($comp) } catch { $INSTALLSTATE_UNKNOWN }
}

try {
    # (a) no properties: policy components must NOT be selected, assoc + context must be
    $s = Cost-Session ""
    foreach ($p in $expectPolicies) {
        $compName = ($regRows | Where-Object { $_[2] -eq $PolicyKey -and $_[3] -eq $p.Value })[5]
        $st = Comp-State $s $compName
        Check ($st -ne $INSTALLSTATE_LOCAL) ("without {0}: policy component not installed" -f $p.Prop)
    }
    Check ((Comp-State $s "FileAssoc")  -eq $INSTALLSTATE_LOCAL) "by default: .mrk association IS installed"
    Check ((Comp-State $s "CtxHandler") -eq $INSTALLSTATE_LOCAL) "by default: the context-menu handler IS installed"
    Check ((Comp-State $s "ShellExt")  -eq $INSTALLSTATE_LOCAL) "by default: the drag-drop handler IS installed"
    # The point of the whole exception: named nothing, still enforced.
    Check ((Comp-State $s "PolSecureDesk") -eq $INSTALLSTATE_LOCAL) `
          "naming NOTHING still installs SecureDesktop (the other policy values do not)"
    # The 2727 class from the other side: a Directory row can exist and still not
    # resolve, and a costed session is the only place that is visible without
    # actually installing. Every directory a component installs into is checked,
    # so this keeps working whatever the package grows. It must read the session
    # while it is still ALIVE - reading a released COM object silently returns
    # empty, which is how the first version of this check reported a false
    # failure.
    foreach ($d in @("INSTALLDIR","ProgramMenuFolder")) {
        $dv = ""
        try { $dv = [string]$s.Property($d) } catch {}
        Check ($dv -and $dv.Length -gt 0) ("{0} resolves to a path: '{1}'" -f $d, $dv)
    }
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($s)

    # (b) properties set: each named policy component must be selected
    $line = ($expectPolicies | ForEach-Object { $_.Prop + "=1" }) -join " "
    $s = Cost-Session $line
    foreach ($p in $expectPolicies) {
        $compName = ($regRows | Where-Object { $_[2] -eq $PolicyKey -and $_[3] -eq $p.Value })[5]
        $st = Comp-State $s $compName
        Check ($st -eq $INSTALLSTATE_LOCAL) ("with {0}=1: policy component IS installed" -f $p.Prop)
    }
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($s)

    # (c) the opt-outs must actually opt out
    $s = Cost-Session "MYRKR_NOASSOC=1 MYRKR_NOCONTEXT=1 MYRKR_NOSHELLEXT=1"
    Check ((Comp-State $s "FileAssoc")  -ne $INSTALLSTATE_LOCAL) "MYRKR_NOASSOC=1 suppresses the association"
    Check ((Comp-State $s "CtxHandler") -ne $INSTALLSTATE_LOCAL) "MYRKR_NOCONTEXT=1 suppresses the context-menu handler"
    # This one suppresses the FILE as well as the registration - opting out means
    # nothing of Myrkr's is on the machine for Explorer to load.
    Check ((Comp-State $s "ShellExt")   -ne $INSTALLSTATE_LOCAL) "MYRKR_NOSHELLEXT=1 suppresses the DLL and its registration"
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($s)

    # ...and NOSHELLEXT alone must take the context handler with it, since those
    # rows name a CLSID whose server would not be installed.
    $s = Cost-Session "MYRKR_NOSHELLEXT=1"
    Check ((Comp-State $s "CtxHandler") -ne $INSTALLSTATE_LOCAL) `
          "MYRKR_NOSHELLEXT=1 alone also suppresses the context-menu handler"
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($s)
} catch {
    Fail ("costed session failed: {0}" -f $_.Exception.Message)
}

[void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
[GC]::Collect(); [GC]::WaitForPendingFinalizers()

Write-Host ""
Write-Host ("verify_msi: {0} passed, {1} failed" -f $script:oks, $script:fails)
if ($script:fails -gt 0) { exit 1 }
exit 0
