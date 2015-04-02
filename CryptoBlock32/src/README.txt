# detours.lib should be in the same directory or figure out how to use cl commandline to specify libpath
# All the libs are #pragma at the beginning of the cpp. I think that should work to make the cl cmd shorter, 
# otherwise just do `cl hookcrypt.cpp crypt32.lib user32.lib advapi32.lib`
cl /LD hookcrypt.cpp
move hookcrypt.dll to C:\hookcrypt.dll (THIS IS ACTUALLY IMPORTANT AS MICROSOFT DOESN'T KNOW HOW TO PROGRAM LONG PATHS)

# All the libs are #pragma at the beginning of the cpp. I think that should work to make the cl cmd shorter, 
# otherwise just do `cl EncryptFile.cpp crypt32.lib user32.lib advapi32.lib`
cl EncryptFile.cpp 

# In registry change:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs to C:\hookcrypt.dll
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs to 1

# Execute and look in C:\ for new files created
EncryptFile.exe in.txt out.enc password