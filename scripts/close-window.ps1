# Post WM_CLOSE to a process's visible top-level window with the given title: the same path as clicking the title-bar X.
param([int]$ProcessId, [string]$Title = "Beaver")
Add-Type @"
using System; using System.Runtime.InteropServices;
public static class Win {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
}
"@
$closed = 0
[Win]::EnumWindows({ param($h, $p) $owner = 0; [Win]::GetWindowThreadProcessId($h, [ref]$owner) | Out-Null
  $text = New-Object System.Text.StringBuilder 256; [Win]::GetWindowText($h, $text, 256) | Out-Null
  if ($owner -eq $ProcessId -and [Win]::IsWindowVisible($h) -and $text.ToString() -eq $Title) { [Win]::PostMessage($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null; $script:closed++ }
  return $true }, [IntPtr]::Zero) | Out-Null
"closed $closed"
