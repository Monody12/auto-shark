Auto-Shark for Windows
======================

Auto-Shark is distributed in two forms:

1. Installer: run AutoShark-Windows-x64-Setup.exe. The wizard asks whether to
   install for the current user (AppData\Local\Programs\Auto-Shark) or for all
   users (Program Files\Auto-Shark, Administrator required). Silent flags:
   /CURRENTUSER and /ALLUSERS. New releases use the same application identity,
   so installing a newer release upgrades the existing copy in place. Analysis
   projects remain under %LOCALAPPDATA%\AutoShark\projects and are not removed
   during upgrades.

2. Portable: extract AutoShark-Windows-x64-Portable.zip. The archive always
   contains a stable AutoShark directory instead of a version-named directory.
   Close Auto-Shark before replacing an older portable copy.

Both packages contain an embedded Python 3.11 runtime and the GUI. They do not
bundle Wireshark or TShark. On first launch, use Edit > Settings to select
tshark.exe when automatic detection does not find it.

GUI: AutoShark.exe
CLI: auto-shark.exe --help

Auto-Shark stores analysis projects outside the program directory by design.
The default is %LOCALAPPDATA%\AutoShark\projects.
