            AES256 Documentation
            ====================

This is an implementation of the AES256 cipher in C++,
supporting a number of block chaining modes. The code
is intended for inclusion as source code into other
programs (but it could, with a bit of reorganization,
also made into a library).

Before you read any further please note:

      I AM NOT A PROFESSIONAL CRYPTOGRAPHER BUT A
      MERE AMATEUR IN THIS FIELD. THIS CODE HASN'T
      BEEN VETTED BY ANY EXPERTS. SHOULD YOU INTEND
      TO USE THE SUPPLIED CODE IN ANY SECURITY-SENSI-
      TIVE SOFTWARE IT'S YOUR RESPONSIBILITY TO CARE-
      FULLY CHECK THAT IT BEHAVES AS EXPECTED.

Beside the 'AES256' class for (byte-oriented) encryption
and decryption of messages with a set of different block
chaining modes, it contains other components. The most
important is an implementation of "basic AES256", which
only deals with single 16 byte wide blocks at a time.
This is derived from a C implementation by Ilya O. Levin,
with contributions by Hal Finney, which can be downloaded
from

     http://www.literatecode.com/aes256

Beside that there is a pseudo-random number generator,
which also uses the basic AES256 code. The other files
are helper classes and other utility headers and programs
for testing the class with the available NIST ("National
Institute of Standards and Technology") test data sets.

If the following text seems to be mostly gibberish to you
you may find some more general information in the file
'Intro.txt' where I try to answer a number of questions
I had to figure out for myself when I started this project.


1) Status of the code

The code hasn't been tested extensively. My short tests
indicate that it works correctly with the data supplied
in the NIST "Advanced Encryption Standard Algorithm
Validation Suite" (AESAVS) for KAT ("Known Answer Tests"),
MMT ("Multi-block Message Tests" and MCT ("Monte Carlo
Tests". The test files can be downloaded from

http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesmmt.zip
http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesmct.zip

This may not be confused with any "official" validation
- which can't be done by the original author anyway!

The code has not been vetted in any way by others yet,
especially not by any experts in cryptography. No
attempts have been made to address potential security
issues like side-channel attacks.

The code also has not been optimized for speed. Instead I
have tried to only use portable C++ and to make it easy
to understand and thus modify (e.g. most people probably
won't need all the different chaining modes or other
features, so they're supposed to be easy to remove).

Currently the following block chaining modes are
supported

  a) Electronic Codebook (ECB)
  b) Cipher Block Chaining (CBC)
  c) Propagating Cipher Block Chaining (PCBC)
  d) Cipher Feedback 128 (CFB-128) (often just called CFB)
  e) Cipher Feedback 8 (CFB-8)
  f) Output Feedback (OFB)
  g) Counter (CTR)

The following padding modes are supported

  a) PKCS5/PKCS7
  b) ISO/IEC 7816-4
  c) ANSI X9.23
  d) all unused bytes set to 0


2) The 'AES256' class

The file 'AES256.cpp' and the corresponding header file,
'AES256.hpp" contain the code for encrypting and decrypting
messages, either passed (and returned) as std::string objects
or by writing to a std::istream and reading from a std::ostream.

2a) Constructors

There are two constructors for an 'AES256' object:

    AES256(std::string     const & key,
           std::string     const & seed,
           AES256::Chaining_Mode   chaining_mode = AES256::CBC,
           AES256::Padding_Mode    padding_mode = AES256::ISO7816_4);

and

    AES256(std::string const     & key,
           AES256::Chaining_Mode   chaining_mode = AES256::CBC,
           AES256::Padding_Mode    padding_mode = AES256::ISO7816_4);

Both require an (at least) 32 byte long key (as a std::string)
and have two optional arguments, the block chaining mode to
use and the padding mode (if applicable for the chaining
mode selected).

The following values can be used for the block chaining modes:

  a) AES56::ECB
  b) AES56::CBC
  c) AES56::PCBC
  d) AES56::CFB or AES56::CFB128
  e) AES56::CFB8
  f) AES56::OFB
  g) AES56::CTR

If the corresponding argument is not supplied AES256::CBC is
used per default.

The values for the padding modes are

  a) AES256::PKCS7
  a) AES256::ANSIX9_23
  a) AES256::ISO7816_4
  a) AES256::ALL_NULL

In PKCS7 padding mode all the unused bytes of a block are set
to the number of unused bytes. In ANSIX9_23 mode all unused
bytes are set to 0 except the very last one, which contains
the number of unused bytes. For ISO7816_4 the first unused
byte in the block is set to 0x80, all remaining ones to 0.
With ALL_NULL all the unused bytes are set to 0 (this mode
is unsuitable for transmitting binary data!).

The important difference between the two constructors is the
'seed' argument, which is missing in the second version. This
'seed' is used as the seed for a pseudo-random number generator,
which generates random initialization vectors (IVs). If the
version of the constructor with the 'seed' argument is used
for each encryption a new, randomly chosen IV is created and
used. It's probably a good idea to do this since one never
should use the same IV again for the same key. To make sure
the IV is as random as possible the seed should be picked to
be truly random (use the best source of randomness available
on your system).

If the second version of the constructor is used the random
generator is seeded with a default seed, which is the same
for each instance of the AES256 class. This is only useful
for testing, where reproducibility of results matters, but
can have devastating effects when used for security critical
applications (which then aren't secure anymore). If you use
the second version (without the 'seed' argument) anyway you
should manually set a different IV for each encryption you 
do, using the 'set_IV()' method.

2b) 'set_IV()' method

    void set_IV(std::string const & IV = std::string());


The 'set_IV()' method allows you to set a new initialization
vector at any time. When not called a different IV is chosen
randomly before each new encryption. If the 'set_IV()' method
has been called with an at least 16 byte long string as its
argument this value is used as the IV for the next encryption
(with the exception of the ECB chaining mode which doesn't use
an IV). During the encryption of each block of 16 bytes (or,
for CFB-8, each byte) the "IV" for the  encryption of the next
block is generated. The resulting "IV" of encrypting the last
block of a messages is then stored and used on the next call
of of the 'encrypt()' method (unless a different one has been
set via 'set_IV()' in between). Also calls of the 'decrypt()'
method will modify the internal "IV" state in a similar way.
For a security critical application a new IV should be set via
the 'set_IV()' method before each call of 'encrypt()' (unless
IVs are set to be chosen at random).

If 'set_IV()' has been called to set an IV you can switch
back to using randomly chosen IVs by calling it again with
an empty std::string (or no argument at all).

2c) 'get_IV()' method

    std::string get_IV() const;

This method returns the current internal state of the "IV", i.e.
the value that will be used for the next encryption when random
selection of IVs is disabled and no call of the 'decrypt()'
method is done in between.

2d) The 'get_key()' methods

    std::string get_key() const;

This method returns the key used for encryption.

2e) 'set_chaining_mode()' method

	void set_chaining_mode(AES256::Chaining_Mode mode);

This method allows to switch between different chaining
modes. The argument can have the same values as already
described above in the documentation of the constructors.

2f) 'set_padding_mode()' method

    void set_padding_mode(AES256::Padding_Mode mode);

This method allows to switch between the different padding
modes. The argument can have the same values as already
described above in the documentation of the constructors.
Note that only some of the block chaining modes (ECB, CBC
and PCBC) require padding, for all others this setting is
irrelevant.

2g) 'uses_padding()' method

    bool uses_padding() const;

Returns if the currently selected block chaining mode uses
padding.

2h) 'encrypt()' methods

    std::string encrypt(std::string const & in,
                        bool                no_padding_block = false);

and

    std::ostream & encrypt(std::istream & in,
                           std::ostream & out,
                           bool           no_padding_block = false);

These methods are to be used for encrypting messages. The
first one expects the message as a std::string (as its
first argument) and returns the encrypted result as
another std::string. The second method tries to read the
message to be encrypted from a std::istream, supplied via
the first argument and writes the result to the std::ostream
from the second argument (which is also the return value).

Note that each message is prepended by a 16 byte wide block
containing the IV used in encrypting the message (if one was
used). Thus, except for ECB mode the result of calling the
'encrypt()' method will always be at least 16 bytes longer
than the input.

Beside, both methods accept a second/third, optional argument,
'no_padding_block'. If set it prevents the methods from writing
out a final full block of (encrypted) padding for block chaining
modes that require padding when the length of the message is an
integer multiple of 16. Per default such full padding blocks are
always written out since without them the receiver of the encrypted
message isn't able to determine were the message ends and padding
begins. But under certain circumstances (i.e. when it's known
in advance that messages always have lengths divisible by 16)
disabling the extra padding blocks can reduce the amount of data
to be transmitted.

2i) 'decrypt()' methods

    std::string decrypt(std::string const & in,
                        bool                no_padding_block = false);

and

    std::ostream & decrypt(std::istream & in,
                           std::ostream & out,
                           bool           no_padding_block = false);

Like their 'encrypt()' counterparts these methods work either
with std:strings or a std::istream and std::ostream pair and
decrypt a message.

Note that the methods both expect the IV used for encrypting to
to be prepended to the encrypted message!

The second/third, optional argument, 'no_padding_block', allows
to instruct the methods not to expect a full (encrypted) block
of padding (for block chaining modes requiring padding) when the
plaintext messages has a length divisible by 16. This only makes
sense (in conjunction with chaining modes requiring padding) when
all messages exchanged have lengths that are multiples of 16 and
the sender and recipient have agreed in advance on dropping such
full padding blocks.


3) Other classes and files

3a) The 'AES256_Base' class

This class, implemented in the files 'AES256_Base.cpp' and
'AES256_Base.cpp' handles the basic, single 16 byte block
encryption and decryption. As pointed out above the code is
derived from C code written and distributed by Ilya O. Levin
et al.. Beside the constructor it contains mostly two methods,
one for encrypting and one for decrypting a block of 16 bytes.

The AES256_Base class uses the S_Box class (for the Rijndael
S-box and its inverse). A note on compiling this part: per
default the Rijndael S-box tables are pre-set, static members
of the class. They are thus part of the executable program and
thus can be found by inspection of the (compiled and linked)
program. Some may object to this (since it may make it easier
to detect that the program uses AES-256). For those there is
a macro that when set avoids having these tables become part
of the executable: if the macro 'CALC_RIJNDAEL_SBOX' is defined
these tables only get generated when the first instance of the
'AES256_Base' class (and thus the 'S_Box' class) is used -
instead of putting the values into the executable. This is
probably only of interest for the truly paranoid and adds a
bit of extra code.

If minimizing the amount of memory used is of utmost importance
the macro 'ON_THE_FLY_RIJNDAEL_SBOX' can be set instead. This
results in no tables being used (which occupy 512 bytes) but
instead the values of the S-box (and its inverse) being com-
puted whenever needed. Note that this can add a lot of extra
computation time. 


3b) The 'AS256_PRNG' class

This class, implemented in 'AS256_PRNG.cpp' and 'AS256_PRNG.hpp',
is a generator of pseudo-random numbers, based on the the AES256
cipher. It is used to provide random initialization vectors for
the 'AES256' class. Beside the constructor (which accepts a
seed which controls the sequence of the generated "random"
bytes) and a method for reseeding the generator it has three
methods for obtaining sets of bytes either as a std::string,
having them put into a user supplied buffer of unsigned chars
or into a 'Byte_Block' object (see below).


3c) The 'Byte_Block' class

The 'Byte_Block' template class, implemented in the file
'Byte_Block.hpp' is a helper class for dealing with the types
of (fixed sized) blocks of bytes used everywhere else. It is
basically an array of N (the template argument) bytes, with a
number of methods useful in the rest of the code. There are
several ways to construct an instance of the class (with
automated addition of padding when the data provided don't
suffice to fill N bytes), methods for accessing or modifying
then, increment, shift and XOR operators, implicit and explicit
conversion to and from other types and data structures.


3d) The 'nist_test.cpp' and 'nist_test_mct.cpp' files

These two files compile to programs that allow to test the
'AES256' class against the test data sets supplied by NIST
(see above in section 1 for the URLs at the time of writing).
The program generated from 'nist_test.cpp' allows to do tests
with the KAT and MTT files (for AES256 and the block chaining
modes supported). 'nist_test_mct.cpp' compiles to a program
for testing the MCT files. Both programs assume that the names
of the NIST supplied test files haven't been modified. They
either print out a success message or, on failure, how many
of the (supported) tests did fail.


4) Compiling

When compiling the code as part of your program the following
files will have to compiled with it:

  a) AES256.cpp
  b) AES256_Base.cpp
  c) AES256_PRNG.cpp

These files require the header files

  a) AES256.hpp
  b) AES256_PRNG.hpp
  c) AES256_Base.hpp
  d) Byte_Block.hpp
  e) Padding_Type.hpp

which, of course, need to be in places were the compiler can
find them.

The 'cpp' files all have some extra code for creating a number
of programs for doing very simple-minded tests. Which of these
(non-essential) parts of the files the compiler "sees" depends on
macros being defined. They are

  a) 'TEST_AES256_STRING'
  b) 'TEST_AES256_STREAM'
  c) 'TEST_AES256_FILE'
  d) 'TEST_AES256_RAND1'
  e) 'TEST_AES256_RAND2'
  f) 'TEST_AES256_BASE'
  g) 'TEST_AES256_BASE_FIPS'

During a compilation only one of these macros may be defined. If
one of them is set an executable test program will be generated.
To find out what these test programs do (and for some examples
of how the functionality can be used) search for the macros in
the 'cpp' files. The 'Makefile' coming with the package creates
all of these "test programs" when executed. It also creates the
two programs for testing with the test suite files supplied by
NIST.


5) Testing with the NIST data sets for AES-256

If you have the NIST test data in a subdirectory named 'NIST
installed and have used the 'Makefile' coming with the package
to create all programs, you can do (assuming a bash-like shell)
e.g.

  for i in NIST/KAT/*256.rsp; do ./nist_test $i; done
  for i in NIST/MMT/*256.rsp; do ./nist_test $i; done
  for i in NIST/MCT/*256.rsp; do ./nist_test_mct $i; done

to run the tests supplied by NIST. All of them should succeed
(except for the unsupported CFB1 mode) -or you've found a bug I'd
be glad to know about! Fell free to write to my email given at
the end.


6) License

This set of files is, in most parts, distributed under the terms
and conditions of the GPL3 (GNU General Public License, version 3).
Exceptions are the files 'AES256_Base.cpp' and 'AES256_Base.hpp' -
since they are derived work they're under the same license as was
chosen by the authors of the original work.


2016/12/20      Jens Thoms Törring    <jt@toerring.de>
