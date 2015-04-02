# Hookcrypt hooks into Microsoft CryptoAPI calls and logs their arguments and outputs into C:\CryptoBlock32.dll
# The file is named .dll to attempt to dodge ransomware encrypting the log file itself. Just open it in notepad. 
# Microsoft Research's Detours is required to be installed from: http://research.microsoft.com/en-us/projects/detours/

#===== GETTING STARTED =====
# This should just work once you have: 
# 1. detours.lib built and placed into the right directory
# 2. Admin privileges / UAC disabled
build.bat foo.dll
install.bat foo.dll
EncryptFile.exe in.txt out.enc password123
-> Check CryptoBlock32.dll

#==============================================================================================================
#====== BUILD =======
# detours.lib should be in the same directory or figure out how to use cl 
# commandline to specify libpath 
# All the libs are #pragma at the beginning of the cpp. I think that should 
# work to make the cl cmd shorter, otherwise just do 
# cl hookcrypt.cpp crypt32.lib user32.lib advapi32.lib
cl /LD hookcrypt.cpp

# All the libs are #pragma at the beginning of the cpp. I think that should work 
# to make the cl cmd shorter, otherwise just do 
# cl EncryptFile.cpp crypt32.lib user32.lib advapi32.lib
cl EncryptFile.cpp 

#====== INSTALL =====
move hookcrypt.dll to C:\hookcrypt.dll (THIS IS ACTUALLY IMPORTANT AS MICROSOFT DOESN'T KNOW HOW TO PROGRAM LONG PATHS)
# In registry change:
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs to C:\hookcrypt.dll
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs to 1

#===== TESTING =====
# Execute some programs that use MS Crypto API and look in C:\ for new files created
EncryptFile.exe in.txt out.enc password123
EncryptFile.exe in.txt out2.enc
DecryptFile out.enc plain1.enc password123
DecryptFile out2.enc plain2.enc
