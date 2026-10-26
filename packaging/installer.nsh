; Beaver's NSIS wizard pages, included by electron-builder (build.nsis.include).
; Installer: welcome → license → install mode → folder → startup options → install → finish.
; Uninstaller: welcome → what to remove → uninstall → finish.
; Updates run silently and never show these pages, so rules and data always survive an upgrade.

!include nsDialogs.nsh

!macro customWelcomePage
  !define MUI_WELCOMEPAGE_TITLE "Welcome to Beaver ${VERSION}"
  !define MUI_WELCOMEPAGE_TEXT "Beaver watches every network connection on this computer, checks it against public threat intelligence, and warns you when someone may be controlling your PC or taking your data.$\r$\n$\r$\nEverything is analysed on this device. No account, no cloud, no telemetry.$\r$\n$\r$\nClick Next to continue."
  !insertmacro MUI_PAGE_WELCOME
!macroend

!ifndef BUILD_UNINSTALLER
  Var beaverStartup
  Var beaverStartupBox
!endif

!macro customPageAfterChangeDir
  Function beaverOptionsCreate
    ${if} ${isUpdated}
      Abort
    ${endIf}
    !insertmacro MUI_HEADER_TEXT "Startup and protection" "Choose how Beaver runs on this computer."
    nsDialogs::Create 1018
    Pop $0
    ${NSD_CreateLabel} 0 0 100% 26u "Beaver protects you best when it starts with Windows, so it can warn you about remote access and threats from the moment you sign in. It starts quietly in the system tray."
    Pop $0
    ${NSD_CreateCheckbox} 0 32u 100% 12u "&Start Beaver when I sign in (recommended)"
    Pop $beaverStartupBox
    ${NSD_Check} $beaverStartupBox
    ${NSD_CreateLabel} 0 60u 100% 26u "Optional: the free Npcap driver adds per-app speeds and website names. Beaver works without it, and its first-run setup can link you to it later."
    Pop $0
    ${NSD_CreateLink} 0 88u 100% 12u "Get Npcap from npcap.com"
    Pop $0
    ${NSD_OnClick} $0 beaverOpenNpcap
    nsDialogs::Show
  FunctionEnd

  Function beaverOpenNpcap
    ExecShell "open" "https://npcap.com/#download"
  FunctionEnd

  Function beaverOptionsLeave
    ${NSD_GetState} $beaverStartupBox $beaverStartup
  FunctionEnd
  Page custom beaverOptionsCreate beaverOptionsLeave
!macroend

; The app applies this once on first launch through its own login-item code, then deletes the file.
!macro customInstall
  !ifndef BUILD_UNINSTALLER
    ${ifNot} ${isUpdated}
    ${andIf} $beaverStartup != ""
      FileOpen $0 "$INSTDIR\resources\installer-options.json" w
      ${if} $beaverStartup == ${BST_CHECKED}
        FileWrite $0 '{"start_at_login": true}'
      ${else}
        FileWrite $0 '{"start_at_login": false}'
      ${endIf}
      FileClose $0
    ${endIf}
  !endif
!macroend

!macro customFinishPage
  Function StartApp
    ${if} ${isUpdated}
      StrCpy $1 "--updated"
    ${else}
      StrCpy $1 ""
    ${endif}
    ${StdUtils.ExecShellAsUser} $0 "$launchLink" "open" "$1"
  FunctionEnd
  !define MUI_FINISHPAGE_TITLE "Beaver is installed"
  !define MUI_FINISHPAGE_TEXT "Beaver lives in the system tray and keeps monitoring when its window is closed. Right-click the tray icon to pause notifications or quit.$\r$\n$\r$\nA short setup opens the first time you start it."
  !define MUI_FINISHPAGE_RUN
  !define MUI_FINISHPAGE_RUN_TEXT "&Open Beaver now"
  !define MUI_FINISHPAGE_RUN_FUNCTION "StartApp"
  !define MUI_FINISHPAGE_LINK "How Beaver decides what is risky"
  !define MUI_FINISHPAGE_LINK_LOCATION "https://github.com/AmoghShukla06/Beaver/blob/main/docs/DETECTION.md"
  !insertmacro MUI_PAGE_FINISH
!macroend

!ifdef BUILD_UNINSTALLER
  Var beaverRemoveRules
  Var beaverRemoveData
  Var beaverRulesBox
  Var beaverDataBox
!endif

!macro customUnWelcomePage
  !define MUI_WELCOMEPAGE_TITLE "Uninstall Beaver"
  !define MUI_WELCOMEPAGE_TEXT "This removes Beaver from your computer.$\r$\n$\r$\nOn the next page you can choose whether to also remove Beaver's firewall rules and your local history.$\r$\n$\r$\nClick Next to continue."
  !insertmacro MUI_UNPAGE_WELCOME
  Function un.beaverChoicesCreate
    !insertmacro MUI_HEADER_TEXT "What should be removed?" "Beaver's program files are always removed."
    nsDialogs::Create 1018
    Pop $0
    ${NSD_CreateCheckbox} 0 0 100% 12u "Remove the &firewall rules Beaver created"
    Pop $beaverRulesBox
    ${NSD_Check} $beaverRulesBox
    ${NSD_CreateLabel} 12u 14u 95% 20u "Unblocks the apps, addresses and ports you blocked with Beaver. Windows will ask for permission."
    Pop $0
    ${NSD_CreateCheckbox} 0 44u 100% 12u "Delete my Beaver &data (history, alerts, settings and logs)"
    Pop $beaverDataBox
    ${NSD_CreateLabel} 12u 58u 95% 20u "Leave this unchecked to keep your history and allowlist if you reinstall later."
    Pop $0
    nsDialogs::Show
  FunctionEnd

  Function un.beaverChoicesLeave
    ${NSD_GetState} $beaverRulesBox $beaverRemoveRules
    ${NSD_GetState} $beaverDataBox $beaverRemoveData
  FunctionEnd
  UninstPage custom un.beaverChoicesCreate un.beaverChoicesLeave
!macroend

!macro customUnInstall
  ${ifNot} ${isUpdated}
    ${if} $beaverRemoveRules == ${BST_CHECKED}
      ExecShell "runas" "powershell.exe" "-NoProfile -NonInteractive -WindowStyle Hidden -Command $\"Get-NetFirewallRule -Group 'Beaver' -ErrorAction SilentlyContinue | Remove-NetFirewallRule$\"" SW_HIDE
    ${endIf}
    ${if} $beaverRemoveData == ${BST_CHECKED}
      ; Electron keeps per-user data under %APPDATA%\<app name>, same paths electron-builder's own cleanup uses.
      RMDir /r "$APPDATA\${APP_FILENAME}"
      !ifdef APP_PRODUCT_FILENAME
        RMDir /r "$APPDATA\${APP_PRODUCT_FILENAME}"
      !endif
    ${endIf}
  ${endIf}
!macroend
