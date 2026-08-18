# Is myrkrshell.dll currently mapped into explorer.exe?
#
#   powershell -File tools\shellext_mapped.ps1            -> report; exit 1 if mapped
#   powershell -File tools\shellext_mapped.ps1 -Restart   -> report, and restart
#                                                            Explorer if it is mapped
#
# WHY THIS EXISTS
#
# Installing a new MSI always rewrites myrkrshell.dll, whatever version it
# claims: make_msi.ps1 schedules RemoveExistingProducts immediately after
# InstallInitialize, so the old product is uninstalled before InstallFiles runs
# and there is no existing file for the installer's version comparison to skip.
# The DLL's version has nothing to do with it.
#
# What that leaves behind is an explorer.exe that may still have the OLD image
# mapped. It is demand-loaded (DllCanUnloadNow is exported) and Explorer drops
# it when idle, so much of the time there is nothing stale to clear and
# restarting Explorer is pure disruption. This says which case you are in.
#
# RUN IT BEFORE THE INSTALL. That is the only moment the answer is meaningful:
# mapped beforehand means the image Explorer holds is the outgoing one and a
# restart is needed afterwards. Mapped only AFTER the install means Explorer
# picked up the new file on its own, and restarting would achieve nothing.
#
# Do not try to decide this by comparing versions instead. A loaded module's
# version information is read from the file at its path, and by the time you
# would look the installer has already replaced that file - so a stale mapping
# and a fresh one report the same number. Presence, plus when you asked, is the
# signal that actually distinguishes them.
[CmdletBinding()]
param([switch]$Restart)

$ErrorActionPreference = "Stop"
$dll = "myrkrshell.dll"

# A process whose module list cannot be read is reported as UNKNOWN and counted
# as mapped: this gates a restart, and the harmless answer is the cautious one.
$mapped  = @()
$unknown = @()
foreach ($p in @(Get-Process explorer -ErrorAction SilentlyContinue)) {
    try {
        $m = $p.Modules | Where-Object { $_.ModuleName -eq $dll }
        if ($m) { $mapped += [pscustomobject]@{ Pid = $p.Id; Path = $m[0].FileName } }
    } catch {
        $unknown += $p.Id
    }
}

if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) {
    Write-Host "explorer.exe is not running - nothing to restart"
    exit 0
}

foreach ($u in $unknown) { Write-Host "  explorer pid $u : module list unreadable - assuming mapped" }
foreach ($m in $mapped)  { Write-Host ("  explorer pid {0} : {1}" -f $m.Pid, $m.Path) }

$needs = ($mapped.Count + $unknown.Count) -gt 0
if (-not $needs) {
    Write-Host "$dll is NOT mapped into explorer.exe - no restart needed"
    exit 0
}

Write-Host "$dll IS mapped into explorer.exe - a restart is needed after installing"
if ($Restart) {
    Stop-Process -Name explorer -Force
    Start-Sleep -Milliseconds 1500
    if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) {
        Start-Process explorer.exe
        Start-Sleep -Milliseconds 1500
    }
    $p = Get-Process explorer -ErrorAction SilentlyContinue
    Write-Host ("restarted; explorer pid {0}" -f (($p.Id) -join ", "))
}
exit 1
