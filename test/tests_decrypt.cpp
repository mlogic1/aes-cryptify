#include "tests_common.h"
#include <aescryptify/codec.h>
#include <iostream>
#include <cassert>

void TestDecrypt()
{
	const std::string originalFile{"./my_vacation_photo.jpg"};
	const std::string originalSHA{GetFileMD5(originalFile)};

	const std::string fileToDecrypt{"./my_secret_self_encrypted.file"};

	const std::string decryptedFile{"./my_decrypted_file.jpg"};
	const std::string keyFile{"./my_secret_manual.key"};

	unsigned char key[AES_KEY_SIZE];
	AesCryptify::LoadKeyFromFile(key, keyFile);
	AesCryptify::DecryptFile(fileToDecrypt, decryptedFile, key);

	const std::string decryptedFileSHA{GetFileMD5(decryptedFile)};

	assert(decryptedFileSHA == originalSHA);
}

int main(int argc, char* argv[])
{
	TestDecrypt();

	return 0;
}
