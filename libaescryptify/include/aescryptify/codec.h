#pragma once

#include <string>

constexpr const int AES_KEY_SIZE = 16;

namespace AesCryptify
{
	void GenerateKey(unsigned char* key);
	void SaveKeyToFile(unsigned char* key, const std::string& outFile);
	void LoadKeyFromFile(unsigned char* key, const std::string& inFile);
	bool EncryptFile(const std::string& inFilePath, const std::string& outFilePath, const unsigned char* key);
	bool DecryptFile(const std::string& inFilePath, const std::string& outFilePath, const unsigned char* key);
}