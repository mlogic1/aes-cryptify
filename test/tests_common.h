#include <aescryptify/codec.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <exception>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

inline std::string GetFileMD5(const std::string& filePath)
{
	// Open file
	std::ifstream file(filePath, std::ios::binary);
	if (!file)
	{
		throw std::runtime_error("Unable to open file");
	}
	// Initialize MD5 context
	MD5_CTX md5Context;
	MD5_Init(&md5Context); // Read file in chunks
	std::vector<char> buffer(1024 * 16); // 16 KB buffer
	while (file.good())
	{
		file.read(buffer.data(), buffer.size());
		MD5_Update(&md5Context, buffer.data(), file.gcount());
	} // Finalize MD5 hash
	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_Final(hash, &md5Context);

	// Convert hash to hexadecimal string
	std::ostringstream oss;
	for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
	{
		oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return oss.str();
}

inline std::string GetFileSHA256(const std::string& filePath)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	std::ifstream file(filePath, std::ifstream::binary);
	if (!file) {
		throw std::runtime_error("Could not open file");
	}
	char buffer[8192];
	while (file.read(buffer, sizeof(buffer))) {
		SHA256_Update(&sha256, buffer, file.gcount());
	}
	SHA256_Update(&sha256, buffer, file.gcount());
	SHA256_Final(hash, &sha256);
	std::stringstream ss;
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}
	return ss.str();
}
