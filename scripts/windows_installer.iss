#ifndef MyAppVersion
  #error MyAppVersion must be supplied by build_windows_release.ps1
#endif
#ifndef MyVersionInfo
  #define MyVersionInfo MyAppVersion + ".0"
#endif
#ifndef SourceDir
  #error SourceDir must point at the staged AutoShark bundle
#endif
#ifndef ReleaseDir
  #error ReleaseDir must point at the release output directory
#endif

#define MyAppName "Auto-Shark"
#define MyAppPublisher "Auto-Shark contributors"
#define MyAppExeName "AutoShark.exe"

[Setup]
AppId={{F4B24FB8-7432-49E0-A0B6-22D154A555F2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyVersionInfo}
DefaultDirName={localappdata}\Programs\Auto-Shark
DefaultGroupName=Auto-Shark
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#ReleaseDir}
OutputBaseFilename=AutoShark-Windows-x64-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=yes
DirExistsWarning=no
Uninstallable=yes
SetupLogging=yes
LicenseFile={#SourceDir}\LICENSE

[InstallDelete]
; PyInstaller can remove or rename dependencies between versions. The runtime
; directory contains no user projects, so clear it before an in-place upgrade.
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Auto-Shark"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Auto-Shark command line"; Filename: "{cmd}"; Parameters: "/K ""{app}\auto-shark.exe"" --help"; WorkingDir: "{app}"
Name: "{group}\Uninstall Auto-Shark"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Auto-Shark"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Auto-Shark"; Flags: nowait postinstall skipifsilent
