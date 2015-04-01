#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "detours.h"
#include <string>

#pragma comment (lib, "advapi32")

static BOOL (WINAPI *Real_CryptDecrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *) = CryptDecrypt;
static BOOL (WINAPI *Real_CryptEncrypt)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE *, DWORD *, DWORD) = CryptEncrypt;

static BOOL (WINAPI *Real_CryptAcquireContext)(HCRYPTPROV *, LPCTSTR, LPCTSTR, DWORD, DWORD) = CryptAcquireContext;
static BOOL (WINAPI *Real_CryptCreateHash)(HCRYPTPROV, ALG_ID , HCRYPTKEY, DWORD, HCRYPTHASH *) = CryptCreateHash;
static BOOL (WINAPI *Real_CryptHashData)(HCRYPTHASH, const BYTE *, DWORD, DWORD) = CryptHashData;
static BOOL (WINAPI *Real_CryptDeriveKey)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY *) = CryptDeriveKey;

const std::string CurrentTime() {
	SYSTEMTIME st;
	GetSystemTime(&st);
	char currentTime[100] = "";
	sprintf(currentTime,"%d:%d:%d %d",st.wHour, st.wMinute, st.wSecond , st.wMilliseconds);
	return std::string(currentTime); 
}

BOOL WINAPI myCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptDecrypt(%x,%x,%x,%x,%p,%p)\n", mytime.c_str(), hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

	fclose(fd);
	return Real_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

BOOL WINAPI myCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptEncrypt(%x,%x,%x,%x,%p,%p, %x)\n", mytime.c_str(), hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
	
	//DWORD dwDataLen;
	//DWORD dwMode = 5;
	//dwDataLen = sizeof(DWORD);
	//if(CryptGetKeyParam(hKey,KP_MODE,(PBYTE)&dwMode,&dwDataLen,0)) {
	//	fprintf(fd,"%x ", dwMode);
	//	fprintf(fd,"%x ", dwDataLen);
	//}
	//else {
    //	fprintf(fd, "Error number %x.\n", GetLastError());
	//}

	fclose(fd);
	return Real_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

BOOL WINAPI myCryptAcquireContext(HCRYPTPROV *phProv, LPCTSTR pszContainer, LPCTSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptAcquireContext(%p,%s,%s,%x,%x)\n", mytime.c_str(), phProv, pszContainer, pszProvider, dwProvType, dwFlags);

	fclose(fd);
	return Real_CryptAcquireContext(phProv, pszContainer, pszProvider, dwProvType, dwFlags);
}

BOOL WINAPI myCryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptCreateHash(%x,%x,%x,%x,%p)\n", mytime.c_str(), hProv, Algid, hKey, dwFlags, phHash);

	fclose(fd);
	return Real_CryptCreateHash(hProv, Algid, hKey,dwFlags, phHash);
}

BOOL WINAPI myCryptHashData(HCRYPTHASH hHash, BYTE *pbData, DWORD dwDataLen, DWORD dwFlags) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptHashData(%x,%p,%x,%x)\n", mytime.c_str(), hHash, pbData, dwDataLen, dwFlags);

	fclose(fd);
	return Real_CryptHashData(hHash, pbData, dwDataLen, dwFlags);
}

BOOL WINAPI myCryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptDeriveKey40(%x,%x,%x,%x,%p)\n", mytime.c_str(), hProv, Algid, hBaseData, dwFlags, phKey);

	// Get the length of the hash
    DWORD dwHashLen;
    DWORD dwHashLenSize = sizeof(DWORD);
	CryptGetHashParam(hBaseData, HP_HASHSIZE, (BYTE *)&dwHashLen, &dwHashLenSize, 0);
	// Get the hash value
    BYTE *pbHash;
    pbHash = (BYTE*)malloc(dwHashLen);
    if(CryptGetHashParam(hBaseData, HP_HASHVAL, pbHash, &dwHashLen, 0)) {
        // Print the hash value.
        fprintf(fd, "The hash is:  ");
        for(int i = 0 ; i < dwHashLen ; i++) {
            fprintf(fd, "%02x ",pbHash[i]);
        }
        fprintf(fd, "\n");
    }

	fclose(fd);
	return Real_CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey);
}


INT APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
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