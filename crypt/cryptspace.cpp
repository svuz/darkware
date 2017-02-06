#include <random>
#include <string>
#include <fstream>
#include "AES256.hpp"
#include "Byte_Block.hpp"
#include "md5.hpp"
#include "cryptspace.hpp"
std::string RANDOM::STR( size_t length ){
		auto randchar = []() -> char{
			const char charset[] ="0123456789"
			"!@#$%^&*"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
			const size_t max_index = (sizeof(charset) - 1);
			return charset[ rand() % max_index ];
		};
		std::string str(length,0);
		std::generate_n( str.begin(), length, randchar );
		return str;
	}

void RANDOM::ENCPATH(){
	std::ifstream ifs("README.md", std::ifstream::in);
	std::ofstream ofs("README.e", std::ifstream::out);
	std::string key("abcdefghijklmnopqrstuvwxyz123456");
	AES256 aes(key);
	aes.encrypt(ifs, ofs);
	ifs.close();
	ofs.close();

	ifs.open("README.enc", std::ifstream::in);
	ofs.open("README.dec", std::ifstream::out);

	aes.decrypt(ifs, ofs);

	ifs.close();
	ofs.close();
}

std::string RANDOM::HASH(std::string newhash){
	return md5(newhash);
}