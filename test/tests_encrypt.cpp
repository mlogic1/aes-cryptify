#include "tests_common.h"
#include <aescryptify/codec.h>
#include <iostream>
#include <cassert>

void TestEncryptWithNewKey()
{
	const std::string originalFile{"./my_vacation_photo.jpg"};
	const std::string originalSHA{GetFileMD5(originalFile)};

	const std::string encryptedFile{"./my_secret.file"};
	const std::string keyFile{"./my_secret.key"};

	unsigned char key[AES_KEY_SIZE];
	AesCryptify::GenerateKey(key);
	AesCryptify::SaveKeyToFile(key, keyFile);
	AesCryptify::EncryptFile(originalFile, encryptedFile, key);
}

void TestEncryptWithExistingKey()
{
	const std::string originalFile{"./my_vacation_photo.jpg"};
	const std::string expected_encrpyptedFileHash{"f434c9138e7e1e8e25663fe218c69cc6"};

	const std::string encryptedFile{"./my_secret_self_encrypted.file"};
	const std::string keyFile{"./my_secret_manual.key"};

	// fixed key
	unsigned char key[AES_KEY_SIZE] = {0x75, 0x2D, 0x48, 0x28, 0xB4, 0x0F, 0xF2, 0x5A, 0x29, 0xEC, 0xF8, 0x55, 0x65, 0x57, 0x19, 0x43};
	AesCryptify::SaveKeyToFile(key, keyFile);
	AesCryptify::EncryptFile(originalFile, encryptedFile, key);

	const std::string originalSHA{GetFileMD5(encryptedFile)};
	assert(expected_encrpyptedFileHash == originalSHA);
}

int main(int argc, char* argv[])
{
	TestEncryptWithNewKey();
	TestEncryptWithExistingKey();

	return 0;
}
