#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "detours.h"

#pragma comment (lib, "advapi32")

static BOOL (WINAPI *Real_CryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *) = CryptDecrypt;
static BOOL (WINAPI *Real_CryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *, DWORD) = CryptEncrypt;

BOOL WINAPI myCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {
	FILE *fd = fopen("C:\\inCryptEncrypt.txt", "w");
	if (fd == NULL) { 
		printf("Failed to open file"); 
	}
	else {
		fprintf(fd, "Hello World!\n");
		fprintf(fd, "hKey = %s\n", hKey);
	}
	fclose(fd);
	return Real_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}
BOOL WINAPI myCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {
	FILE *fd = fopen("C:\\inCryptDecrypt.txt", "w");
	if (fd == NULL) { 
		printf("Failed to open file"); 
	}
	else {
		fprintf(fd, "Hello World!\n");
		fprintf(fd, "hKey = %s\n", hKey);
	}
	fclose(fd);
	return Real_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

INT APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved) {
	FILE *fd = fopen("C:\\DllLoaded2.txt","w");
	switch(Reason) {
	case DLL_PROCESS_ATTACH:
		fprintf(fd, "Made it to process_attach\n");
		fclose(fd);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)Real_CryptEncrypt, myCryptEncrypt);
		DetourTransactionCommit();
		break;
	
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)Real_CryptEncrypt, myCryptEncrypt);
		DetourTransactionCommit();
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}