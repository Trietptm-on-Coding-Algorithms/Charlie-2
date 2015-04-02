#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "detours.h"
#include <string>

#pragma comment (lib, "advapi32")
#pragma comment (lib, "user32")
#pragma comment (lib, "crypt32")
#pragma comment (lib, "detours")

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

const std::string stringify_buffer(BYTE *pbData, DWORD dwDataLen) {
	char cstrData[1000] = "";
	DWORD cstrDataLen = 0;
	for (int i = 0; i < dwDataLen; i++) {
		cstrData[i] = pbData[i];
		cstrDataLen++;
	}
	cstrData[cstrDataLen] = '\0';
	return std::string(cstrData); 
}

BOOL WINAPI myCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptDecrypt(%x,%x,%x,%x,%p,%p)\n", mytime.c_str(), hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

    
    // MSDN specifies these which can be useful to reverse/bruteforce with: 
    // all: KP_ALGID, KP_BLOCKLEN, KP_CERTIFICATE, KP_KEYLEN, KP_SALT, KP_PERMISSIONS
    // if DSS: KP_P, KP_Q, KP_G
    // if block cipher: KP_MODE, KP_PADDING, KP_IV, KP_EFFECTIVE_KEYLEN

	DWORD dwDataLen;
	BYTE *pbData2;
    // GET KP_ALGID
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_ALGID, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
    pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_ALGID, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_ALGID:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

    // GET KP_BLOCKLEN
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_BLOCKLEN, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_BLOCKLEN, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_BLOCKLEN:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

	// GET KP_CERTIFICATE
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d\n", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_CERTIFICATE, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_CERTIFICATE:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

    // GET KP_KEYLEN
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_KEYLEN, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_KEYLEN, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_KEYLEN:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

    // GET KP_SALT
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_SALT, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_SALT, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_SALT:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

    // GET KP_PERMISSIONS
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_PERMISSIONS, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_PERMISSIONS, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_PERMISSIONS:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

	fclose(fd);
	return Real_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

BOOL WINAPI myCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptEncrypt(%x,%x,%x,%x,%p,%p, %x)\n", mytime.c_str(), hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
	
    // MSDN specifies these which can be useful to reverse/bruteforce with: 
    // all: KP_ALGID, KP_BLOCKLEN, KP_CERTIFICATE, KP_KEYLEN, KP_SALT, KP_PERMISSIONS
    // if DSS: KP_P, KP_Q, KP_G
    // if block cipher: KP_MODE, KP_PADDING, KP_IV, KP_EFFECTIVE_KEYLEN

	DWORD dwDataLen;
	BYTE *pbData2;
    // GET KP_ALGID
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_ALGID, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
    pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_ALGID, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_ALGID:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

    // GET KP_BLOCKLEN
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_BLOCKLEN, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_BLOCKLEN, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_BLOCKLEN:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

	// GET KP_CERTIFICATE
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d\n", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_CERTIFICATE, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_CERTIFICATE:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

    // GET KP_KEYLEN
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_KEYLEN, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_KEYLEN, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_KEYLEN:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

    // GET KP_SALT
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_SALT, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_SALT, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_SALT:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

    // GET KP_PERMISSIONS
    dwDataLen = 0;
	CryptGetKeyParam(hKey, KP_PERMISSIONS, NULL, &dwDataLen, 0);
	fprintf(fd, "data size = %d ", dwDataLen);
	pbData2 = (BYTE*)malloc(dwDataLen);
	CryptGetKeyParam(hKey, KP_PERMISSIONS, pbData2, &dwDataLen, 0);
	// Print the data value.
    fprintf(fd, "KP_PERMISSIONS:  ");
    for(int i = 0 ; i < dwDataLen ; i++) {
    	fprintf(fd, "%02x ",pbData2[i]);
    }
    fprintf(fd, "\n");
    free(pbData2);

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

	// TODO(eugenek): Maybe add printing of hProv properties, not sure it adds much if AcquireContext was added as 
	// all the info should be there

	fclose(fd);
	return Real_CryptCreateHash(hProv, Algid, hKey,dwFlags, phHash);
}

BOOL WINAPI myCryptHashData(HCRYPTHASH hHash, BYTE *pbData, DWORD dwDataLen, DWORD dwFlags) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptHashData(%x,%p,%x,%x)\n", mytime.c_str(), hHash, pbData, dwDataLen, dwFlags);

	fprintf(fd, "data to hash = %s\n\n", stringify_buffer(pbData, dwDataLen).c_str());

	fclose(fd);
	return Real_CryptHashData(hHash, pbData, dwDataLen, dwFlags);
}

BOOL WINAPI myCryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey) {
	FILE *fd = fopen("C:\\CryptoBlock32.txt", "a");
	std::string mytime = CurrentTime();
	fprintf(fd, "%s myCryptDeriveKey(%x,%x,%x,%x,%p)\n", mytime.c_str(), hProv, Algid, hBaseData, dwFlags, phKey);

	// Get the length of the hash
    DWORD dwHashLen;
    DWORD dwHashLenSize = sizeof(DWORD);
	CryptGetHashParam(hBaseData, HP_HASHSIZE, (BYTE *)&dwHashLen, &dwHashLenSize, 0);
	fprintf(fd, "hash size = %d\n", dwHashLen);

	// Get the hash value
    BYTE *pbHash;
    pbHash = (BYTE*)malloc(dwHashLen);
    CryptGetHashParam(hBaseData, HP_HASHVAL, pbHash, &dwHashLen, 0);
    // Print the hash value.
    fprintf(fd, "The hash is:  ");
    for(int i = 0 ; i < dwHashLen ; i++) {
    	fprintf(fd, "%02x ",pbHash[i]);
    }
    fprintf(fd, "\n\n");

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