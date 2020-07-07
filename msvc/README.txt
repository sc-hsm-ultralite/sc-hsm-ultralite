To compile with Visual Studio 2015+ you need the following (only x86) components:

%ProgramFiles(x86)%\Microsoft Visual Studio 12.0\VC
%ProgramFiles(x86)%\Microsoft SDKs\Windows\v7.1A

It might be a big task to install the needed components.
For convenience locate the 7z archive: "...\install\Microsoft\VC12+SDK7.1A for compiling XP target with VS2019.7z" 
and extract everything to %ProgramFiles(x86)% (needs admin rights).


The SDK needs the following registry entries (see SDKv7.1A.reg):
[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows\v7.1A]
"InstallationFolder"="C:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v7.1A\\"
"ProductVersion"="7.1.51106"

Note: WOW6432Node is only needed if you use the x64 RegEdit.exe.
