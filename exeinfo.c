/*
 * EXEINFO - reveals secrets about DOS and Win16 EXE headers
 *
 * Blake Burgess
 * 6 November 2016
 *
 * See: http://www.delorie.com/djgpp/doc/exe/
 *      ... for information about the MZ header
 *      http://www.program-transformation.org/Transform/NeFormat
 *      ... for information about the NE header
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct mz_header_struct
{
    short signature;    // "MZ"
    short lastBlock;    // Number of bytes in last block used
    short blocksInFile; // Number of blocks in the program
    short numRelocs;    // Number of relocation entries after header
    short headerParas;  // Number of paragraphs in the header
    short minExtraParas;// Number of paragraphs of additional required memory
    short maxExtraParas;// Number of paragraphs of maximum required memory
    short ss;           // Relative stack segment location
    short sp;           // Initial SP value
    short checksum;     // Checksum
    short ip;           // Initial IP value
    short cs;           // Initial CS value
    short relocTableOfs;// Pointer to relocation table
    short overlayNumber;// Overlay number
} mz_header;

void printMZ(mz_header* header)
{
    printf(
        "00 : %04X : Signature\n"
        "02 : %04X : Number of bytes in last block used\n"
        "04 : %04X : Number of blocks in the program\n"
        "06 : %04X : Number of relocation entries after header\n"
        "08 : %04X : Number of paragraphs in the header\n"
        "0A : %04X : Number of paragraphs of additional required memory\n"
        "0C : %04X : Number of paragraphs of maximum required memory\n"
        "0E : %04X : Relative stack segment location\n"
        "10 : %04X : Initial SP value\n"
        "12 : %04X : Checksum\n"
        "14 : %04X : Initial IP value\n"
        "16 : %04X : Initial CS value\n"
        "18 : %04X : Pointer to relocation table\n"
        "1A : %04X : Overlay number\n",
        header->signature,
        header->lastBlock,
        header->blocksInFile,
        header->numRelocs,
        header->headerParas,
        header->minExtraParas,
        header->maxExtraParas,
        header->ss,
        header->sp,
        header->checksum,
        header->ip,
        header->cs,
        header->relocTableOfs,
        header->overlayNumber
    );
}

void printHelp()
{
    printf("EXEINFO displays information about EXE headers.\n"
           "Usage: EXEINFO <file>\n");
}

int main(int argc, char *argv[])
{
    FILE *exe;
    mz_header *exemz;
    size_t exemz_readsize;
    
    if (argc < 2 || argc > 2)
    {
        printHelp();
        return 0;
    }

    if (argv[1][0] == '/')
    {
        printHelp();
        return 0;
    }

    exe = fopen(argv[1], "rb");

    if (exe == 0)
    {
        printf("Could not open '%s'\n", argv[1]);
        return 1;
    }

    exemz_readsize = fread(exemz, sizeof(mz_header), 28, exe);

    if (exemz_readsize != 28)
    {
        printf("Read error\n");
        return 1;
    }

    printMZ(exemz);
    
    return 0;
}
