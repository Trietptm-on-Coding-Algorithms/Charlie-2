cl /LD hookcrypt.cpp /Fehookcrypt.dll
cl EncryptFile.cpp
cl DecryptFile.cpp
move hookcrypt.dll C:\
REM I can't seem to get the reg add to work, so do it manually with regedit
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\" /v AppInit_DLLs /t REG_SZ /d \"C:\hookcrypt.dll"

