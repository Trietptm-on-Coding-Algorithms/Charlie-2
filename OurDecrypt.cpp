/*
16:15:37 209 myCryptAcquireContext(0013F744,(null),Microsoft Enhanced Cryptographic Provider v1.0,1,0)
16:15:37 219 myCryptGenKey(1eb3e0,6801,800001,0013F748)
16:15:37 219 myCryptExportKey(1faff0,1fb030,1,0,00000000,0013F740)
16:15:37 219 myCryptExportKey(1faff0,1fb030,1,0,001FE438,0013F740)
16:15:37 219 myCryptEncrypt(1faff0,0,1,0,001FE438,0013F74C, 3f0)
*/
#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <multimon.h>
#include <winuser.h>

// Link with the Advapi32.lib file.
#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "crypt32")

int _tmain(int argc, _TCHAR* argv[]) {
    LPTSTR pszSourceFile = argv[1]; 
    LPTSTR pszDestinationFile = argv[2]; 

    HCRYPTKEY hKey = NULL; 
    HCRYPTHASH hHash = NULL; 
    HCRYPTPROV hCryptProv = NULL; 
    DWORD dwCount;
    PBYTE pbBuffer = NULL; // Fill this in with the source data
    DWORD dwBlockLen; 
    DWORD dwBufferLen; 
    
    
    //-- Create the source and destination file
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE; 
    
    hSourceFile = CreateFile(pszSourceFile, 
            FILE_READ_DATA,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    
    hDestinationFile = CreateFile(
            pszDestinationFile, 
            FILE_WRITE_DATA,
            FILE_SHARE_READ,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    //--END

    //-- Pull out the key from the encypted file
    PBYTE pbKeyBlob = NULL; // Fill this in with the key val
    DWORD dwKeyBlobLen; // Fill this in with the key len
    // Read the length of the key
    ReadFile(hSourceFile,
            &dwKeyBlobLen, 
            sizeof(DWORD), 
            &dwCount, 
            NULL);
    pbKeyBlob = (PBYTE)malloc(dwKeyBlobLen);
    // Read the value of the key
    ReadFile(hSourceFile, 
            pbKeyBlob, 
            dwKeyBlobLen, 
            &dwCount, 
            NULL);
    //--END

    //-- Set up decryption
    // 16:15:37 209 myCryptAcquireContext(0013F744,(null),Microsoft Enhanced Cryptographic Provider v1.0,1,0)
    CryptAcquireContext(&hCryptProv, /* Output w/ the CSP */
            NULL, /* From Log */
            "Microsoft Enhanced Cryptographic Provider v1.0", /* From Log */
            1, /* From Log */
            0 ); /* From Log */

    // 16:15:37 219 myCryptExportKey(1faff0,1fb030,1,0,00000000,0013F740)
    CryptImportKey(
            hCryptProv, /* Generated previously */
            pbKeyBlob, /* Key val extracted from file/log */
            dwKeyBlobLen, /* Key length extracted from file/log */
            0, /* From log */
            0, /* From log */
            &hKey); /* Output w/ the key */
    //--END

    //-- Decrypt the file
    pbBuffer = (PBYTE)malloc(1000);
    ReadFile(
            hSourceFile, 
            pbBuffer, 
            1000, /* Block size from log */
            &dwCount, 
            NULL); 

    // 16:15:37 219 myCryptEncrypt(1faff0,0,1,0,001FE438,0013F74C, 3f0)
    CryptDecrypt(
            hKey, /* Generated prevously */
            0, /* From log */
            1, /* Generated previously */
            0, /* From log */
            pbBuffer, /* Input buffer */
            &dwCount); /* Input length */
    
    //--END

    // AND WE'RE DONE !
    WriteFile(
            hDestinationFile, 
            pbBuffer, 
            dwCount,
            &dwCount,
            NULL);
    // Free some stuff
    free(pbBuffer);
    CloseHandle(hSourceFile);
    CloseHandle(hDestinationFile);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);
    return true;

}