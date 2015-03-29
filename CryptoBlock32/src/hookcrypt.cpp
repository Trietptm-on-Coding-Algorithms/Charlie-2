#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "detours.h"


static BOOL (WINAPI *Real_CryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *) = CryptDecrypt;

BOOL WINAPI myCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {
	printf("in cryptdecrypt");
	return Real_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

INT APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved) {
	switch(Reason) {
	case DLL_PROCESS_ATTACH:	
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)Real_CryptDecrypt, myCryptDecrypt);
		DetourTransactionCommit();
		break;
	
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)Real_CryptDecrypt, myCryptDecrypt);
		DetourTransactionCommit();
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}