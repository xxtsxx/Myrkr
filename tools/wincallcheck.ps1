# Audit WINCALL sites for arguments that read a register the macro has already
# overwritten.
#
# WINCALL's order (macros.inc):
#   1. stack args (positions 5+) emitted FIRST, in forward order; __WSTKARG uses
#      RAX as scratch for 64-bit memory values
#   2. then register args in REVERSE: r9 <- a4, r8 <- a3, rdx <- a2, rcx <- a1
#
# So by the time argN is assigned, every HIGHER-numbered register target already
# holds its new value:
#   a1 (-> rcx) must not read rdx / r8 / r9
#   a2 (-> rdx) must not read r8 / r9
#   a3 (-> r8)  must not read r9
#   a4 (-> r9)  is assigned first, so it is always safe
# and with 5+ args, any register arg reading RAX may see stack-marshalling
# scratch instead.
param([switch]$Strict)
# The tree, not one machine's copy of it.  This was an absolute path, which is
# also why it was never wired into build.cmd: it only ran where it was written.
$root = Join-Path (Split-Path -Parent $PSScriptRoot) "src"

function Split-Args([string]$s) {
  $out=@(); $depth=0; $cur=""
  foreach ($ch in $s.ToCharArray()) {
    if ($ch -eq '<' -or $ch -eq '[') { $depth++ }
    elseif ($ch -eq '>' -or $ch -eq ']') { $depth-- }
    if ($ch -eq ',' -and $depth -eq 0) { $out += $cur.Trim(); $cur="" } else { $cur += $ch }
  }
  if ($cur.Trim()) { $out += $cur.Trim() }
  ,$out
}
# register families: matching any member means the arg depends on that register
$fam = @{
  'rdx' = '\b(rdx|edx|dx|dl)\b'
  'r8'  = '\b(r8|r8d|r8w|r8b)\b'
  'r9'  = '\b(r9|r9d|r9w|r9b)\b'
  'rax' = '\b(rax|eax|ax|al)\b'
}
$findings = @()
Get-ChildItem "$root\*.asm" | ForEach-Object {
  $file = $_.Name
  $ln = 0
  foreach ($line in (Get-Content $_.FullName)) {
    $ln++
    if ($line -notmatch '^\s*WINCALL\s+([A-Za-z_][\w@]*)\s*,\s*(.+)$') { continue }
    $fn = $Matches[1]; $rest = $Matches[2] -replace ';.*$',''
    $a = Split-Args $rest
    $n = $a.Count
    for ($i=0; $i -lt [Math]::Min($n,4); $i++) {
      $pos = $i + 1
      $danger = @()
      # a register is only clobbered if the call HAS an argument targeting it
      if ($pos -le 1 -and $n -ge 2) { $danger += 'rdx' }
      if ($pos -le 2 -and $n -ge 3) { $danger += 'r8'  }
      if ($pos -le 3 -and $n -ge 4) { $danger += 'r9'  }
      foreach ($d in $danger) {
        if ($a[$i] -match $fam[$d]) {
          $findings += [pscustomobject]@{ File=$file; Line=$ln; Fn=$fn; Pos=$pos; Arg=$a[$i]; Clobbered=$d }
        }
      }
      if ($n -ge 5 -and $a[$i] -match $fam['rax']) {
        $findings += [pscustomobject]@{ File=$file; Line=$ln; Fn=$fn; Pos=$pos; Arg=$a[$i]; Clobbered='rax (stack-arg scratch)' }
      }
    }
    # stack args after the first that lean on rax are also suspect
    for ($i=4; $i -lt $n; $i++) {
      if ($i -gt 4 -and $a[$i] -match $fam['rax']) {
        $findings += [pscustomobject]@{ File=$file; Line=$ln; Fn=$fn; Pos=($i+1); Arg=$a[$i]; Clobbered='rax (earlier stack arg)' }
      }
    }
  }
}
$sites = ((Get-ChildItem "$root\*.asm" | ForEach-Object { Select-String -LiteralPath $_.FullName -Pattern '^\s*WINCALL' }) | Measure-Object).Count
"WINCALL sites scanned : $sites"
"Suspect sites         : $($findings.Count)"
""
if ($findings.Count) {
  $findings | Sort-Object File,Line | ForEach-Object {
    "{0}:{1}  {2}  arg{3} = '{4}'   reads {5} AFTER it is overwritten" -f $_.File,$_.Line,$_.Fn,$_.Pos,$_.Arg,$_.Clobbered
  }
}

# A checker that prints and exits 0 whatever it finds cannot gate anything, and
# this one did exactly that - which is the other half of why it was never in
# build.cmd.  The floor comes from tools/floors.py so there is still only one
# place floors live, whatever language the checker is written in.
$floorRc = 0
$py = (Get-Command python -ErrorAction SilentlyContinue)
if ($py) {
  & $py.Source (Join-Path $PSScriptRoot "floors.py") wincallcheck "sites=$sites"
  $floorRc = $LASTEXITCODE
} else {
  "wincallcheck: python not found - coverage floor NOT checked"
}
if ($findings.Count -gt 0 -or $floorRc -ne 0) { exit 1 }
exit 0

