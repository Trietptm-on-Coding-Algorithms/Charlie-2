#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "detours.h"

#pragma comment (lib, "advapi32")

static BOOL (WINAPI *Real_CryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *) = CryptDecrypt;
static BOOL (WINAPI *Real_CryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *, DWORD) = CryptEncrypt;

static BOOL (WINAPI *Real_CryptAcquireContext)(HCRYPTPROV *, LPCTSTR, LPCTSTR, DWORD, DWORD) = CryptAcquireContext;
static BOOL (WINAPI *Real_CryptCreateHash)(HCRYPTPROV, ALG_ID , HCRYPTKEY, DWORD, HCRYPTHASH *) = CryptCreateHash;
static BOOL (WINAPI *Real_CryptHashData)(HCRYPTHASH, const BYTE *, DWORD, DWORD) = CryptHashData;
static BOOL (WINAPI *Real_CryptDeriveKey)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY *) = CryptDeriveKey;

BOOL WINAPI myCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {
	FILE *fd = fopen("C:\\inCryptDecrypt.txt", "a");
	fprintf(fd, "myCryptDecrypt(%x,%x,%x,%x,%p,%p)\n", hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
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

BOOL WINAPI myCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {
	FILE *fd = fopen("C:\\inCryptEncrypt.txt", "a");
	fprintf(fd, "myCryptEncrypt(%x,%x,%x,%x,%p,%p, %x)\n", hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
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

BOOL WINAPI myCryptAcquireContext(HCRYPTPROV *phProv, LPCTSTR pszContainer, LPCTSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
	FILE *fd = fopen("C:\\inCryptAcquireContext.txt", "w");
	fprintf(fd, "myCryptAcquireContext(%p,%s,%s,%x,%x)\n", phProv, pszContainer, pszProvider, dwProvType, dwFlags);
	fclose(fd);
	return Real_CryptAcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

BOOL WINAPI myCryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash) {
	FILE *fd = fopen("C:\\inCryptCreateHash.txt", "w");
	// Fix this one from all s
	fprintf(fd, "myCryptCreateHash(%x,%x,%x,%x,%p)\n", hProv, Algid, hKey, dwFlags, phHash);
	fclose(fd);
	return Real_CryptCreateHash(hProv, Algid, hKey,dwFlags, phHash);
}

BOOL WINAPI myCryptHashData(HCRYPTHASH hHash, BYTE *pbData, DWORD dwDataLen, DWORD dwFlags) {
	FILE *fd = fopen("C:\\inCryptHashData.txt", "w");
	fprintf(fd, "myCryptHashData(%x,%p,%x,%x)\n", hHash, pbData, dwDataLen, dwFlags);
	fclose(fd);
	return Real_CryptHashData(hHash, pbData, dwDataLen, dwFlags);
}

BOOL WINAPI myCryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey) {
	FILE *fd = fopen("C:\\inCryptDeriveKey.txt", "w");
	fprintf(fd, "myCryptDeriveKey(%x,%x,%x,%x,%p)\n", hProv, Algid, hBaseData, dwFlags, phKey);
	fclose(fd);
	return Real_CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey);
}


INT APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved) {
	FILE *fd = fopen("C:\\DllLoaded10.txt","w");
	switch(Reason) {
	case DLL_PROCESS_ATTACH:
		// DetourRestoreAfterWith(); ?
		fprintf(fd, "Made it to process_attach\n");
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)Real_CryptEncrypt, myCryptEncrypt);
		DetourAttach(&(PVOID&)Real_CryptDecrypt, myCryptDecrypt);
		DetourAttach(&(PVOID&)Real_CryptAcquireContext, myCryptAcquireContext);
		DetourAttach(&(PVOID&)Real_CryptCreateHash, myCryptCreateHash);
		DetourAttach(&(PVOID&)Real_CryptHashData, myCryptHashData);
		DetourAttach(&(PVOID&)Real_CryptDeriveKey, myCryptDeriveKey);
		DetourTransactionCommit();
		fprintf(fd, "Made it out of process_attach\n");
		break;
	
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)Real_CryptEncrypt, myCryptEncrypt);
		DetourDetach(&(PVOID&)Real_CryptDecrypt, myCryptDecrypt);
		DetourDetach(&(PVOID&)Real_CryptAcquireContext, myCryptAcquireContext);
		DetourDetach(&(PVOID&)Real_CryptCreateHash, myCryptCreateHash);
		DetourDetach(&(PVOID&)Real_CryptHashData, myCryptHashData);
		DetourDetach(&(PVOID&)Real_CryptDeriveKey, myCryptDeriveKey);
		DetourTransactionCommit();
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;
	}
	fclose(fd);
	return TRUE;
}