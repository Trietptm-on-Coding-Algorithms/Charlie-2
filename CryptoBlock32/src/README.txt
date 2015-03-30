# detours.lib should be in the same directory or figure out how to use cl commandline to specify libpath
cl /LD hookcrypt.cpp crypt32.lib detours.lib advapi32.lib
move hookcrypt.dll to C:\hookcrypt.dll (THIS IS ACTUALLY IMPORTANT AS MICROSOFT DOESN'T KNOW HOW TO PROGRAM LONG PATHS)

# I think the user32.lib is actually pointless and it gets pulled in anyway, but it isn't hurting to put it in? 
cl EncryptFile.cpp user32.lib

# In registry change:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs to C:\hookcrypt.dll
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs to 1

# Execute and look in C:\ for new files created
EncryptFile.exe in.txt out.enc
