; Uninstall: offer to remove Beaver's firewall rules (group "Beaver"). Skipped for silent runs and for the
; uninstall electron-updater performs while installing an update, so blocks survive upgrades.
!macro customUnInstall
  ${ifNot} ${isUpdated}
    IfSilent beaver_keep_rules
    MessageBox MB_YESNO|MB_ICONQUESTION "Remove the firewall rules Beaver created?$\r$\n$\r$\nChoose No to keep your blocks in place. Windows will ask for permission." /SD IDNO IDNO beaver_keep_rules
    ExecShell "runas" "powershell.exe" "-NoProfile -NonInteractive -WindowStyle Hidden -Command $\"Get-NetFirewallRule -Group 'Beaver' -ErrorAction SilentlyContinue | Remove-NetFirewallRule$\"" SW_HIDE
    beaver_keep_rules:
  ${endIf}
!macroend
