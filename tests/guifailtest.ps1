# Two window regressions from the 1.1.3 review, both invisible to the CLI suites.
#
# 1. A failed encrypt or decrypt showed its error and then FELL THROUGH into the
#    container-edit tail of on_done, which showed a second, unrelated dialog
#    ("The full re-encryption could not be completed") and skipped od_restore -
#    the step that clears the typed password.  A tampered single-file container
#    is decrypted here and every message box counted: exactly one is correct.
#
# 2. The About window draws "github.com/xxtsxx/Myrkr" at its foot, and the main
#    About box used to claim a version label opened the project page while
#    nothing did.  The foot is now a real link: WM_NCHITTEST must say HTCLIENT
#    (clickable) on it and HTCAPTION (drag) beside it.  The link is NOT clicked -
#    that would launch the user's browser.
#
# Needs a dbg build (MYRKR_DBG_NOSECDESK, and encrypt -p for the fixture).
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$exe  = Join-Path $root 'bin\myrkr.exe'
$work = Join-Path ([IO.Path]::GetTempPath()) ('myrkr-guifail-' + [guid]::NewGuid().ToString('N').Substring(0,8))
$fail = 0
Add-Type @'
using System; using System.Text; using System.Runtime.InteropServices;
public class GF {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")] public static extern IntPtr Text(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", EntryPoint="SendMessageW")] public static extern IntPtr Send(IntPtr h, uint m, UIntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int l,t,r,b; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  public static IntPtr Find(uint pid, string cls) { IntPtr f=IntPtr.Zero;
    EnumWindows(delegate(IntPtr h, IntPtr u) { uint o; GetWindowThreadProcessId(h,out o);
      if(o!=pid||!IsWindowVisible(h)) return true; var s=new StringBuilder(256); GetClassName(h,s,256);
      if(s.ToString()==cls){f=h;return false;} return true; }, IntPtr.Zero); return f; }
  public static string Title(IntPtr h) { var s=new StringBuilder(512); GetWindowText(h,s,512); return s.ToString(); }
  public static int Hit(IntPtr h, int sx, int sy) { return (int)Send(h, 0x84, UIntPtr.Zero, (IntPtr)(long)(sy * 65536 + sx)); }
}
'@
function WaitFor($p, $cls, $n = 100) {
  for ($i = 0; $i -lt $n; $i++) {
    $h = [GF]::Find([uint32]$p.Id, $cls); if ($h -ne [IntPtr]::Zero) { return $h }
    Start-Sleep -Milliseconds 100
  }
  return [IntPtr]::Zero
}
New-Item -ItemType Directory $work | Out-Null
$old = $env:MYRKR_DBG_NOSECDESK
$p = $null
try {
  # ---- 1. one dialog for one failed decrypt ---------------------------------
  $src = Join-Path $work 'doc.txt'; $mrk = Join-Path $work 'doc.mrk'
  [IO.File]::WriteAllText($src, ('secret line ' * 4000))
  $s = Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList @('encrypt',$src,'-o',$mrk,'-p','Test-Password-9','--store','-m','8','-t','1') -Wait -PassThru
  if ($s.ExitCode -ne 0) { throw "fixture encrypt failed: $($s.ExitCode)" }
  Remove-Item -LiteralPath $src
  $b = [IO.File]::ReadAllBytes($mrk); $b[$b.Length - 200] = $b[$b.Length - 200] -bxor 1; [IO.File]::WriteAllBytes($mrk, $b)
  $env:MYRKR_DBG_NOSECDESK = '1'
  $p = Start-Process -WindowStyle Hidden -FilePath $exe -ArgumentList $mrk -PassThru
  $prompt = WaitFor $p 'myrkr_secdesk'
  if ($prompt -eq [IntPtr]::Zero) { throw 'no password prompt' }
  [void][GF]::Text([GF]::GetDlgItem($prompt, 156), 12, [IntPtr]::Zero, 'Test-Password-9')
  [void][GF]::PostMessageW($prompt, 0x111, [IntPtr]104, [IntPtr]::Zero)
  $main = WaitFor $p 'myrkr_window'
  if ($main -eq [IntPtr]::Zero) { throw 'no main window' }
  Start-Sleep -Milliseconds 800
  [void][GF]::PostMessageW($main, 0x111, [IntPtr]104, [IntPtr]::Zero)      # Decrypt
  $titles = @()
  for ($k = 0; $k -lt 4; $k++) {
    $d = WaitFor $p 'myrkr_mbox' 40
    if ($d -eq [IntPtr]::Zero) { break }
    $titles += [GF]::Title($d)
    [void][GF]::PostMessageW($d, 0x111, [IntPtr]104, [IntPtr]::Zero)       # OK
    Start-Sleep -Milliseconds 400
  }
  if ($titles.Count -eq 1 -and $titles[0] -eq 'Myrkr - error') { 'PASS a failed decrypt shows exactly one dialog' }
  else { "FAIL a failed decrypt showed $($titles.Count) dialog(s): $($titles -join ' | ')"; $fail++ }
  if (-not (Test-Path (Join-Path $work 'doc.txt'))) { 'PASS no plaintext output survives the failed decrypt' }
  else { 'FAIL plaintext output left behind'; $fail++ }
  $p.Kill(); $p.WaitForExit(); $p = $null

  # ---- 2. the About window's link -------------------------------------------
  $p = Start-Process -FilePath $exe -ArgumentList 'help' -PassThru
  $about = WaitFor $p 'myrkr_about'
  if ($about -eq [IntPtr]::Zero) { throw 'no About window' }
  $r = New-Object GF+RECT; [void][GF]::GetWindowRect($about, [ref]$r)
  # Window-relative points; the About window is borderless, so the window rect
  # IS the client rect.  The link sits 30..230 px across, 30..10 px up from the bottom.
  $cases = @(
    @{ n = 'on the link';           x = $r.l + 60;  y = $r.b - 20; want = 1 },
    @{ n = 'beside the link';       x = $r.l + 300; y = $r.b - 20; want = 2 },
    @{ n = 'the body (drag area)';  x = $r.l + 200; y = $r.t + 40; want = 2 }
  )
  foreach ($c in $cases) {
    $got = [GF]::Hit($about, $c.x, $c.y)
    if ($got -eq $c.want) { "PASS About: $($c.n) hit-tests as $got" }
    else { "FAIL About: $($c.n) hit-tests as $got, want $($c.want)"; $fail++ }
  }
} finally {
  if ($p -and -not $p.HasExited) { $p.Kill() }
  if ($null -eq $old) { Remove-Item Env:\MYRKR_DBG_NOSECDESK -EA SilentlyContinue } else { $env:MYRKR_DBG_NOSECDESK = $old }
  if ((Split-Path $work -Leaf) -like 'myrkr-guifail-*') { Remove-Item -LiteralPath $work -Recurse -Force -EA SilentlyContinue }
}
if ($fail) { "$fail FAILURE(S)"; exit 1 } else { 'guifailtest: all checks passed'; exit 0 }
