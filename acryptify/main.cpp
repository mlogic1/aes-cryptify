#include <aescryptify/codec.h>
#include <iostream>
#include <filesystem>
#include <string>
#include <tuple>
#include <exception>
#include <unistd.h>

namespace sfs = std::filesystem;

void PrintUsage()
{
	static const std::string helpMsg =
R"(usage: acryptify -i input_file [-o ouput_file] [-k key_file]

input_file  - File to be encrypted. Original input file will remain intact.

output_file - Destination where the encrypted file will be stored.
              If -o parameter is not specified, output file will be placed where the input file is with
              a different extension (.enc).

key_file    - 128 bit AES key file used to encrypt the input file.
              If -k parameter is not specified, a new key will be generated and placed where the output file
              is. The key will have a .key extension.)";
	std::cout << helpMsg << std::endl;
}

std::tuple<std::string, std::string, std::string> ProcessArguments(int argc, char* argv[])
{
	std::string inputFile{""};
	std::string outputFile{""};
	std::string keyFile{""};
	int opt;
	while ((opt = getopt(argc, argv, "i:o:k:")) != -1)
	{
		switch (opt) {
			case 'i':
			{
				if (optarg)
				{
					inputFile = optarg;
				}
				break;
			}
			case 'o':
			{
				if (optarg)
				{
					outputFile = optarg;
				}
				break;
			}
			case 'k':
			{
				if (optarg)
				{
					keyFile = optarg;
				}
				break;
			}
			default:
				PrintUsage();
				break;
		}
	}
	return std::make_tuple(inputFile, outputFile, keyFile);
}

int main(int argc, char* argv[])
{
	try
	{
		auto args = ProcessArguments(argc, argv);
		std::string inputFilePath = std::get<0>(args);
		std::string outputFilePath = std::get<1>(args);
		std::string keyFilePath = std::get<2>(args);
		unsigned char key[AES_KEY_SIZE];

		if (inputFilePath.empty())
		{
			PrintUsage();
			return 0;
		}

		sfs::path infilePath(inputFilePath);
		if (!sfs::is_regular_file(sfs::path(inputFilePath)))
		{
			throw std::runtime_error("Input file not found.");
			return -1;
		}

		if (outputFilePath.empty())
		{
			sfs::path outPath = infilePath;
			outPath.replace_extension("enc");
			outputFilePath = outPath;
			if (sfs::is_regular_file(outPath))
			{
				throw std::runtime_error("Output filename already exists.");
			}
		}

		if (keyFilePath.empty())
		{
			sfs::path keyPath = outputFilePath;
			keyFilePath = keyPath.replace_extension("key");
			AesCryptify::GenerateKey(key);
			if (sfs::is_regular_file(keyFilePath))
			{
				std::string errorMessage = "Key cannot be generated, there is already a file at: " + keyFilePath;
				throw std::runtime_error(errorMessage);
			}
			else
			{
				AesCryptify::SaveKeyToFile(key, keyFilePath);
			}
		}
		else
		{
			if (!sfs::is_regular_file(sfs::path(keyFilePath)))
			{
				throw std::runtime_error("Key file does not exist");
			}
			AesCryptify::LoadKeyFromFile(key, keyFilePath);
		}

		if (sfs::is_regular_file(outputFilePath))
		{
			throw std::runtime_error("Output file already exists");
		}

		if(!AesCryptify::EncryptFile(inputFilePath, outputFilePath, key))
		{
			return -1;
		}
	}
	catch(std::runtime_error& err)
	{
		std::cerr << err.what() << std::endl;
		return -1;
	}

	return 0;
}
