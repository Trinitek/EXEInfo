/*
 * EXEINFO - reveals secrets about DOS and Win16 EXE headers
 *
 * Blake Burgess
 * 6 November 2016
 *
 * See: http://www.delorie.com/djgpp/doc/exe/
 *      ... for information about the MZ header
 *		http://www.fileformat.info/format/exe/corion-ne.htm
 *      http://www.program-transformation.org/Transform/NeFormat
 *		http://benoit.papillault.free.fr/c/disc2/exefmt.txt
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

/*
	This NE executable header is also known as a "segmented EXE header".
*/
typedef struct
{
	unsigned short signature;		// "NE"
	unsigned char linkerVersion;	// Linker version
	unsigned char linkerRevision;	// Linker revision
	unsigned short entryTableOfs;	// Offset to entry table
	unsigned short entryTableSize;	// Number of bytes in the entry table
	unsigned long int crc;			// CRC checksum
	unsigned short flags;			// Program load flags (See NE_FLAG_* flags)
	unsigned short autoSeg;			// Segment number of auto data segment
	unsigned short initialHeap;		// Number of bytes of heap to allocate at startup
	unsigned short initialStack;	// Number of bytes of stack space to allocate at startup
	unsigned short cs;				// CS segment number
	unsigned short ip;				// Initial IP value
	unsigned short ss;				// SS segment number
	unsigned short sp;				// Initial SP value
	unsigned short numSegmentTable;	// Number of entries in the segment table
	unsigned short numModRefTable;	// Number of entries in the module reference table
	unsigned short nrTableSize;		// Number of bytes in the non-resident name table
	unsigned short segTableOfs;		// Offset to the segment table
	unsigned short resTableOfs;		// Offset to the resource table
	unsigned short resNameTableOfs;	// Offset to the resident name table
	unsigned short modRefTableOfs;	// Offset to the module reference table
	unsigned short impNameTableOfs;	// Offset to the imported names table
	unsigned long int nrNameTableOfs; // Offset to the non-resident name table
	unsigned short movableEntries;	// Number of movable entries in the entry table
	unsigned short sectorAlignment;	// Logical sector alignment shift count
	unsigned short resourceEntries;	// Number of resource entries
	unsigned char exeType;			// Executable type (See NE_EXE_* defines)
	unsigned char otherFlags;		// Other program property flags (See NE_EXE_OTHER_* flags)
	unsigned short fastOfs;			// Sector offset to the fast-load area (Windows only)
	unsigned short fastSize;		// Number of sectors in the fast-load area (Windows only)
	unsigned short minCodeSwapSize;	// Minimum size of the code swap area (Windows only)
	unsigned char winRevision;		// Expected Windows revision (Windows only)
	unsigned char winVersion;		// Expected Windows version (Windows only)
} ne_header;

#define NE_FLAG_NOAUTODATA		0x0000	// NOAUTODATA
#define NE_FLAG_SINGLEDATA		0x0001	// Shared automatic data segment
#define NE_FLAG_MULTIPLEDATA	0x0002	// Instanced automatic data segment
#define NE_FLAG_LINKERROR		0x2000	// Errors during linking; will not load
#define NE_FLAG_LIBRARY			0x8000	// Library module; SS:SP invalid, CS:IP points to an init procedure

#define NE_EXE_UNKNOWN			0x00	// Unknown
#define NE_EXE_OS2				0x01	// OS/2
#define NE_EXE_WIN				0x02	// Windows
#define NE_EXE_DOS4				0x03	// European MS-DOS 4.x
#define NE_EXE_WIN386			0x04	// Windows 386
#define NE_EXE_BOSS				0x05	// Borland OS Services

#define NE_OTHER_WIN2			0x01	// Windows 2.x app that can run in 3.x protected mode
#define NE_OTHER_PROPORTIONAL	0x02	// Windows 2.x app that supports proportional fonts
#define NE_OTHER_FASTLOAD		0x03	// Contains a fast-load area

/*
	The segment table contains an entry for each segment in the executable file.
	The number of segment table entries are defined in the NE header. The first
	entry in the segment table is segment number 1.
*/
typedef struct
{
	unsigned short dataOfs;			// Logical-sector offset to the segment data
	unsigned short dataSize;		// Length of the segment data in bytes
	unsigned short flags;			// Flags (See NE_SEGTABLE_* flags)
	unsigned short minAllocSize;	// Minimum allocation size of the segment in bytes
} ne_segment_table;

#define NE_SEGTABLE_TYPE_MASK	0x0007	// Segment-type field
#define NE_SEGTABLE_CODE		0x0000	// Code-segment type
#define NE_SEGTABLE_DATA		0x0001	// Data-segment type
#define NE_SEGTABLE_MOVEABLE	0x0010	// Segment is not fixed
#define NE_SEGTABLE_PRELOAD		0x0040	// Segment will be preloaded; read-only if data segment
#define NE_SEGTABLE_RELOCINFO	0x0100	// Contains relocation records
#define NE_SEGTABLE_DISCARD		0xF000	// Discard priority

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
