#include <aescryptify/codec.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <string>
#include <cstring>
#include <iomanip>
#include <tuple>
#include <exception>
#include <unistd.h>

namespace sfs = std::filesystem;

namespace AesCryptify
{
	void GenerateKey(unsigned char* key)
	{
		if (!RAND_bytes(key, AES_BLOCK_SIZE))
		{
			throw std::runtime_error("Unable to create key");
		}
	}

	void SaveKeyToFile(unsigned char* key, const std::string& outFile)
	{
		std::ofstream keyFile;
		keyFile.open(outFile, std::ios::out | std::ios::binary);
		if (keyFile.is_open())
		{
			keyFile.write(reinterpret_cast<const char*>(key), AES_BLOCK_SIZE);
			keyFile.close();
		}
		else
		{
			throw std::runtime_error("Unable to write the key file for writing.");
		}
	}

	void LoadKeyFromFile(unsigned char* key, const std::string& inFile)
	{
		std::ifstream keyFile;
		keyFile.open(inFile, std::ios::in | std::ios::binary | std::ios::ate);
		if (keyFile.is_open())
		{
			std::streamsize fileSize = keyFile.tellg();
			if (fileSize != AES_BLOCK_SIZE)
			{
				throw std::runtime_error("Specified key file does not appear to be a 128bit AES key.");
			}
			keyFile.seekg(0, std::ios::beg);
			keyFile.read(reinterpret_cast<char*>(key), AES_BLOCK_SIZE);
			keyFile.close();
		}
		else
		{
			throw std::runtime_error("Unable to open key file.");
		}
	}

	bool EncryptFile(const std::string& inFilePath, const std::string& outFilePath, const unsigned char* key)
	{
		AES_KEY encryptKey;
		AES_set_encrypt_key(key, 128, &encryptKey);

		std::ifstream inFile(inFilePath, std::ios::binary);
		std::ofstream outFile(outFilePath, std::ios::binary);

		unsigned char inBuffer[AES_BLOCK_SIZE];
		unsigned char outBuffer[AES_BLOCK_SIZE];

		while (inFile.read(reinterpret_cast<char*>(inBuffer), AES_BLOCK_SIZE) || inFile.gcount() > 0)
		{
			AES_encrypt(inBuffer, outBuffer, &encryptKey);
			outFile.write(reinterpret_cast<char*>(outBuffer), AES_BLOCK_SIZE);

			std::memset(inBuffer, 0, AES_BLOCK_SIZE);
		}

		outFile.close();
		inFile.close();

		return true;
	}

	bool DecryptFile(const std::string& inFilePath, const std::string& outFilePath, const unsigned char* key)
	{
		AES_KEY encryptKey;
		AES_set_decrypt_key(key, 128, &encryptKey);

		std::ifstream inFile(inFilePath, std::ios::binary | std::ios::ate);
		std::ofstream outFile(outFilePath, std::ios::binary);

		unsigned char inBuffer[AES_BLOCK_SIZE];
		unsigned char outBuffer[AES_BLOCK_SIZE];

		const uint64_t inputFileSize = inFile.tellg();
		inFile.seekg(std::ios::beg);
		uint64_t totalReadBytes = 0;
		while (inFile.read(reinterpret_cast<char*>(inBuffer), AES_BLOCK_SIZE) || inFile.gcount() > 0)
		{
			totalReadBytes += inFile.gcount();
			AES_decrypt(inBuffer, outBuffer, &encryptKey);

			if (totalReadBytes >= inputFileSize)
			{
				// ignore the ending zeroes when writing the final block
				std::streamsize remainingByteCount = AES_BLOCK_SIZE;
				uint32_t index = AES_BLOCK_SIZE - 1;
				while(outBuffer[index] == 0x00)
				{
					--remainingByteCount;
					--index;
					if (index < 0)
						break;
				}
				outFile.write(reinterpret_cast<char*>(outBuffer), remainingByteCount);
			}
			else
			{
				outFile.write(reinterpret_cast<char*>(outBuffer), AES_BLOCK_SIZE);
			}

			std::memset(outBuffer, 0, AES_BLOCK_SIZE);
		}

		outFile.close();
		inFile.close();

		return true;
	}

	// Not used
	void PrintKey(const unsigned char* key)
	{
		for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
			std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]) << ' ';
		}
		std::cout << std::dec << std::endl; // Reset to decimal output
	}
}
