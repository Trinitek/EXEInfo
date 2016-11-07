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
#include <stdbool.h>
#include <stdlib.h>

typedef struct
{
    unsigned short signature;       // "MZ"
    unsigned short lastBlock;       // Number of bytes in last block used
    unsigned short blocksInFile;    // Number of blocks in the program
    unsigned short numRelocs;       // Number of relocation entries after header
    unsigned short headerParas;     // Number of paragraphs in the header
    unsigned short minExtraParas;   // Number of paragraphs of additional required memory
    unsigned short maxExtraParas;   // Number of paragraphs of maximum required memory
    unsigned short ss;              // Relative stack segment location
    unsigned short sp;              // Initial SP value
    unsigned short checksum;        // Checksum
    unsigned short ip;              // Initial IP value
    unsigned short cs;              // Initial CS value
    unsigned short relocTableOfs;   // Pointer to relocation table
    unsigned short overlayNumber;   // Overlay number
} mz_header;

typedef struct
{
    short offset;
    short segment;
} mz_reloc;

void printHelp()
{
    printf("EXEINFO displays information about EXE headers.\n"
           "Usage: EXEINFO <file>\n");
}

void printMZ(mz_header* header)
{
    printf(
        "[DOS MZ HEADER]\n"
        "0000 | %04X | Signature\n"
        "0002 | %04X | Number of bytes in last block used\n"
        "0004 | %04X | Number of blocks in the program\n"
        "0006 | %04X | Number of relocation entries after header\n"
        "0008 | %04X | Number of paragraphs in the header\n"
        "000A | %04X | Number of paragraphs of additional required memory\n"
        "000C | %04X | Number of paragraphs of maximum required memory\n"
        "000E | %04X | Relative SS location\n"
        "0010 | %04X | Initial SP value\n"
        "0012 | %04X | Checksum\n"
        "0014 | %04X | Initial IP value\n"
        "0016 | %04X | Initial CS value\n"
        "0018 | %04X | Pointer to relocation table\n"
        "001A | %04X | Overlay number\n",
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

void printMZReloc(mz_reloc *mzReloc, unsigned short offset, unsigned int entry)
{
    printf(
        "%04X | %04X:%04X | MZ Reloc %d\n",
        offset, mzReloc->segment, mzReloc->offset, entry
    );
}

bool parseMZReloc(FILE *exeFile, mz_header *exeMz)
{
    size_t readsize;
    mz_reloc *relocs;
    unsigned short i;
    unsigned short relocOfs;

    relocs = malloc(exeMz->numRelocs * sizeof(mz_reloc));
    
    readsize = fread(relocs, sizeof(mz_reloc), exeMz->numRelocs, exeFile);
    
    if (readsize != (unsigned short) exeMz->numRelocs)
    {
        printf("Read error\n");
        free(relocs);
        return false;
    }
    
    relocOfs = exeMz->relocTableOfs;
    
    for (i = 0; i < exeMz->numRelocs; i++)
    {
        printMZReloc(&relocs[i], relocOfs, i);
        relocOfs += sizeof(mz_reloc);
    }
    
    free(relocs);
    return true;
}

/*void ok()
{
    printf("Ok\n");
}*/

bool parseMZ(FILE *exeFile, mz_header *exeMz)
{
    size_t mz_readsize;
    
    mz_readsize = fread(exeMz, sizeof(mz_header), 28, exeFile);
    
    if (mz_readsize != 28)
    {
        printf("Read error\n");
        return false;
    }

    printMZ(exeMz);
    
    printf("\n[DOS MZ RELOCATIONS]\n");
    
    return parseMZReloc(exeFile, exeMz);
}

bool parseNE(FILE *exeFile)
{
    // TODO
    return true;
}

int main(int argc, char *argv[])
{
    FILE *exeFile;
    mz_header *exeMz;
    
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

    exeFile = fopen(argv[1], "rb");

    if (exeFile == 0)
    {
        printf("Could not open '%s'\n", argv[1]);
        return 1;
    }

	exeMz = malloc(sizeof(mz_header));

    parseMZ(exeFile, exeMz);
    
    free(exeMz);
    
    return 0;
}
