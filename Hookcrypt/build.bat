:: This works from `Developer Command Prompt for VS2012` on Win7, that's the 
:: easiest way and comes installed with VS2012. As it opens in Admin mode and 
:: has ENV set up for you. All you have to do is 'DIR <dir with hookcrypt' 
:: and run this bat
cl /LD hookcrypt.cpp /Fehookcrypt.dll
cl EncryptFile.cpp
cl DecryptFile.cpp
move hookcrypt.dll C:\
REM I can't seem to get the reg add to work, so do it manually with regedit
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\" /v AppInit_DLLs /t REG_SZ /d \"C:\hookcrypt.dll"