#include "shred/shredder.hpp"
#include "crypt/AES256.hpp"
#include "crypt/Byte_Block.hpp"
#include "crypt/cryptspace.hpp"
#include <cstdio>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
using namespace std;

#if defined SHREDDER
bool CheckUser();

void info(){
	unsigned long  hdd_size;
	long black= 1024*1024*1024;
	struct statvfs fsinfo;
	statvfs("/", &fsinfo);
	hdd_size = fsinfo.f_frsize*fsinfo.f_blocks;
	cout <<"Disk size : "<<hdd_size/black<<"G"<<"\nDon't Try to CLOSE TERMINAL/KILL PROCESS"<<endl;
}
int main(){
    ShredIt black;
    bool root=CheckUser();
    if(root!=0){cout<<"YOU ARE NOT ROOT !"<<endl;exit(1);}
    else{
    	info();
    	black.RunShreder("msg.img");
    }

}

bool CheckUser(){
    int user=getuid();if(user==0){return 0;}else{return 1;}
}
#endif

AES256::AES256(std::string const & key,
               std::string const & seed,
               Chaining_Mode       chaining_mode,
               Padding_Mode        padding_mode)
    : m_aes256_base(key)
    , m_prng(seed)
    , m_use_random_IV(true)
{
    set_chaining_mode(chaining_mode);
    set_padding_mode(padding_mode);
}


/*---------------------------------------------*
 * Constructor without a seed for random generator, only
 * the 32 byte key is required. The optional second and
 * third arguments select the "chaining mode" and the the
 * "padding mode" and default to Cipher Block Chaining
 * (CBC) and ISO/IEC 7816-4 padding. This constructor
 * should only be used when a different IV is set for each
 * new encryption or during testing!
 *---------------------------------------------*/

AES256::AES256(std::string const & key,
               Chaining_Mode       chaining_mode,
               Padding_Mode        padding_mode)
    : m_aes256_base(key)
    , m_use_random_IV(true)
{
    set_chaining_mode(chaining_mode);
    set_padding_mode(padding_mode);
}


/*---------------------------------------------*
 * Selects a new block cipher mode
 *---------------------------------------------*/

void
AES256::set_chaining_mode(Chaining_Mode mode)
{
    m_mode = mode;

    // Set the function pointers to be used for encryption and decryption
    // in the new mode

    switch (mode) {
    case CTR :
        enc = dec = &AES256::ctr;
        m_use_padding = false;
        break;

       default :
           throw std::invalid_argument("Invalid chaining mode requested");
    }
}


/*---------------------------------------------*
 * Sets the padding mode (for 16 byte blocks only, other
 * block sizes don't need padding)
 *---------------------------------------------*/

void
AES256::set_padding_mode(Padding_Mode mode)
{
    Byte_Block<16>::set_padding_mode(mode);
}


/*---------------------------------------------*
 * Sets a new IV. If called without an argument (or an
 * empty string) switches back to using a randomly
 * chosen IV. 
 *---------------------------------------------*/

void
AES256::set_IV(std::string const & IV)
{
    if (! IV.empty()) {
        if (IV.size() < 16)
            throw std::invalid_argument("IV must contain at least "
                                        "16 bytes of data");

        m_IV = IV;
        m_use_random_IV = false;
    } else {
        m_use_random_IV = true;
    }
}


/*---------------------------------------------*
 * Returns the (current state of the) IV as a string.
 * A useful result is only to be expected if an IV
 * has been set via the set_IV() method!
 *---------------------------------------------*/

std::string
AES256::get_IV() const
{
    return m_IV.as_string();
}


/*---------------------------------------------*
 * Returns the key as a string
 *---------------------------------------------*/

std::string
AES256::get_key() const
{
    return m_aes256_base.get_key().as_string();
}


/*---------------------------------------------*
 * Returns if the currently set chaining mode
 * uses padding
 *---------------------------------------------*/

bool
AES256::uses_padding() const
{
    return m_use_padding;
}

/*---------------------------------------------*
 * Encrypts data from a std::istream, writing the
 * result to a std::ostream.
 *---------------------------------------------*/

std::ostream &AES256::encrypt(std::istream & in, std::ostream &out, bool no_padding_block)
{
    // Make sure streams can read from and written to

    if (in.fail() || out.fail())
        throw std::invalid_argument("Bad input or output stream");


    // Encrypt and write out all 16 byte long segments of the message

    Byte_Block<16> buf;
    while (in.read(buf, 16))
        out.write((this->*enc)(buf), 16);

    // For modes that require padding add it and write out the full 16 byte
    // wide encrypted data (unless 'no_padding_block' is set also add a full
    // block of padding if the message length was divisible by 16, i.e.
    // nothing got read in the last time round). For the other modes encrypt
    // an "incomplete buffer and write out only as many bytes as were in the
    // input.

    if (m_use_padding) {
        if (! (in.gcount() == 0 && no_padding_block))
            out.write((this->*enc)(buf.pad(in.gcount())), 16);
    } else {
        out.write((this->*enc)(buf), in.gcount());
    }

    if (in.bad() || out.bad())
        throw std::invalid_argument("Bad input or output stream");

    return out;
}


/*---------------------------------------------*
 * Decrypts a string, returning a new one. If 'no_padding_block' is set
 * don't expect a full block of trailing padding for messages that
 * had a length that was an integer multiple of 16.
 *---------------------------------------------*/

std::string
AES256::decrypt(std::string const & in,
                bool                no_padding_block)
{
    size_t len = in.size();
    bool bad_len = false;

    switch (m_mode) {
    case CTR :
        bad_len = len < 16;
        break;

    default :
        bad_len = len < (no_padding_block ? 16 : 32) || len % 16;
    }

    if (bad_len)
        throw std::invalid_argument("Length of string to decrypt is "
                                    "incorrect");

    // Get the IV, it's the first block of 16 bytes (except in ECB mode
    // which doesn't use one)

    size_t start = 16;

    // Decrypt what remains

    std::string out;
    for (size_t i = start; i < len; i += 16) {
        Byte_Block<16> buf(in, i);
        out.append((this->*dec)(buf).as_string(   m_use_padding
                                               && ! no_padding_block
                                               && i == len - 16));
    }

    if (! m_use_padding)
        out.erase(len - 16);

    return out;
}


/*---------------------------------------------*
 * Decrypts data from a std::istream, writing the
 * result to a std::ostream.
 *---------------------------------------------*/

std::ostream &
AES256::decrypt(std::istream & in,
                std::ostream & out,
                bool           no_padding_block)
{
    // Make sure streams can read from and written to

    if (in.bad() || out.bad())
        throw std::invalid_argument("Bad input or output stream");
        
    // Decrypt what else we can read in

    Byte_Block<16> buf;
    while (in.read(buf, 16)) {
        // If the mode uses padding and this is the very last block
        // padding bytes have to be removed after decryption.

        if (m_use_padding && ! no_padding_block && in.peek() == EOF) {
            std::string tmp = (this->*dec)(buf).as_string(true);
            out.write(tmp.data(), tmp.size());
        } else {
            out.write((this->*dec)(buf), 16);
        }
    }

    // For modes tha use padding the number of bytes that could be read
    // must be an integer multiple of 16, so nothing should be left. For
    // the other modes decrypt the incomplete buffer and only write as many
    // bytes to the stream as were read in.

    if (in.gcount() != 0) {
        if (m_use_padding)
            throw std::invalid_argument("Bad input stream");
        else
            out.write((this->*dec)(buf), in.gcount());
    }

    // Check for I/O errors

    if (in.bad() || out.bad())
        throw std::invalid_argument("Bad input or output stream");

    return out;
}



/*---------------------------------------------*
 * Counter (CTR) mode encryption and decryption
 *---------------------------------------------*/

Byte_Block<16> &
AES256::ctr(Byte_Block<16> & buf)
{
    Byte_Block<16> tmp = m_IV++;

    m_aes256_base.encrypt(tmp);
    return buf ^= tmp;
}

#if defined AES256_FILE

#include "crypt/md5.hpp"
#include <fstream>

int main(){
    std::cout<<RANDOM::HASH(RANDOM::STR(32))<<std::endl;
    return 0;

}

#endif