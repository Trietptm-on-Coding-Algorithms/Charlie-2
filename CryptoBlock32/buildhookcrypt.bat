# Creates a DLL. https://msdn.microsoft.com/en-us/library/2kzt1wy3.aspx
"cl /LD hookcrypt.cpp wincrypt32.lib detours.lib"
"MAKE THE CRYPTOBLOCK DIRECTORY AND PUT THE DLL THERE"
"reg add \"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\" /v AppInit_DLLs /t REG_SZ /d \"C:\CryptoBlock\hookcrypt.dll\""

