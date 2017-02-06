CXX 	 ?= g++
SOURCES  := crypt/AES256_PRNG.cpp crypt/AES256_Base.cpp crypt/S_Box.cpp crypt/md5.cpp crypt/cryptspace.cpp
HEADERS  := crypt/cryptspace.hpp crypt/md5.hpp crypt/AES256.hpp crypt/AES256_PRNG.hpp crypt/AES256_Base.hpp crypt/Byte_Block.hpp crypt/S_Box.hpp crypt/Padding_Type.hpp
CXXFLAGS := -O3 -ggdb -Wall -Wextra
SHREDDER := shred/shredder.hpp shred/shredder.cpp

all: shredder darkware

shredder:
	nasm -f bin shred/boot.asm -o msg.img
	$(CXX) $(CXXFLAGS) -DSHREDDER main.cpp $(SHREDDER) -o $@

darkware: $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) -DAES256_FILE -o $@ main.cpp $(SOURCES) 
clean:
	rm *.o darkware shredder