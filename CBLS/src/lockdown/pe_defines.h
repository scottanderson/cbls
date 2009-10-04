#ifndef __PE_HEADER_H
#define __PE_HEADER_H

#pragma once

#define FIELD_OFFSET(type, field)    ((long)(long)&(((type *)0)->field))

#define IMAGE_DOS_SIGNATURE                 0x5A4D

#define IMAGE_NT_SIGNATURE                  0x00004550  

typedef struct _IMAGE_DOS_HEADER {      
    unsigned short   e_magic;                     
    unsigned short   e_cblp;                     
    unsigned short   e_cp;                       
    unsigned short   e_crlc;                    
    unsigned short   e_cparhdr;                   
    unsigned short   e_minalloc;                 
    unsigned short   e_maxalloc;                  
    unsigned short   e_ss;                        
    unsigned short   e_sp;                       
    unsigned short   e_csum;                      
    unsigned short   e_ip;                       
    unsigned short   e_cs;                       
    unsigned short   e_lfarlc;                   
    unsigned short   e_ovno;                    
    unsigned short   e_res[4];                   
    unsigned short   e_oemid;                     
    unsigned short   e_oeminfo;                   
    unsigned short   e_res2[10];               
    long   e_lfanew;                    
 } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;


typedef struct _IMAGE_FILE_HEADER {
    unsigned short    Machine;
    unsigned short    NumberOfSections;
    unsigned long   TimeDateStamp;
    unsigned long   PointerToSymbolTable;
    unsigned long   NumberOfSymbols;
    unsigned short    SizeOfOptionalHeader;
    unsigned short    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20

typedef struct _IMAGE_DATA_DIRECTORY {
    unsigned long   VirtualAddress;
    unsigned long   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {


    unsigned short    Magic;
    unsigned char    MajorLinkerVersion;
    unsigned char    MinorLinkerVersion;
    unsigned long   SizeOfCode;
    unsigned long   SizeOfInitializedData;
    unsigned long   SizeOfUninitializedData;
    unsigned long   AddressOfEntryPoint;
    unsigned long   BaseOfCode;
    unsigned long   BaseOfData;

 
    unsigned long   ImageBase;
    unsigned long   SectionAlignment;
    unsigned long   FileAlignment;
    unsigned short    MajorOperatingSystemVersion;
    unsigned short    MinorOperatingSystemVersion;
    unsigned short    MajorImageVersion;
    unsigned short    MinorImageVersion;
    unsigned short    MajorSubsystemVersion;
    unsigned short    MinorSubsystemVersion;
    unsigned long   Win32VersionValue;
    unsigned long   SizeOfImage;
    unsigned long   SizeOfHeaders;
    unsigned long   CheckSum;
    unsigned short    Subsystem;
    unsigned short    DllCharacteristics;
    unsigned long   SizeOfStackReserve;
    unsigned long   SizeOfStackCommit;
    unsigned long   SizeOfHeapReserve;
    unsigned long   SizeOfHeapCommit;
    unsigned long   LoaderFlags;
    unsigned long   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER    224
#define IMAGE_NT_OPTIONAL_HDR_MAGIC      0x10b

typedef struct _IMAGE_NT_HEADERS {
    unsigned long Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((unsigned long)ntheader +                                              \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   

#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   
#define IMAGE_DIRECTORY_ENTRY_TLS             9   
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   
#define IMAGE_DIRECTORY_ENTRY_IAT            12   
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   


#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    unsigned char    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            unsigned long   PhysicalAddress;
            unsigned long   VirtualSize;
    } Misc;
    unsigned long   VirtualAddress;
    unsigned long   SizeOfRawData;
    unsigned long   PointerToRawData;
    unsigned long   PointerToRelocations;
    unsigned long   PointerToLinenumbers;
    unsigned short    NumberOfRelocations;
    unsigned short    NumberOfLinenumbers;
    unsigned long   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

typedef struct _IMAGE_RELOCATION {
    union {
        unsigned long   VirtualAddress;
        unsigned long   RelocCount;             
    };
    unsigned long   SymbolTableIndex;
    unsigned short    Type;
} IMAGE_RELOCATION;

typedef IMAGE_RELOCATION *PIMAGE_RELOCATION;

#define IMAGE_SIZEOF_RELOCATION         10

typedef struct _IMAGE_BASE_RELOCATION {
    unsigned long   VirtualAddress;
    unsigned long   SizeOfBlock;
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION *PIMAGE_BASE_RELOCATION;

#define IMAGE_SIZEOF_BASE_RELOCATION         8

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MIPS_JMPADDR          5
#define IMAGE_REL_BASED_MIPS_JMPADDR16        9
#define IMAGE_REL_BASED_IA64_IMM64            9
#define IMAGE_REL_BASED_DIR64                 10

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    unsigned long   Characteristics;
    unsigned long   TimeDateStamp;
    unsigned short    MajorVersion;
    unsigned short    MinorVersion;
    unsigned short    NumberOfNamedEntries;
    unsigned short    NumberOfIdEntries;
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {
        struct {
            unsigned long NameOffset:31;
            unsigned long NameIsString:1;
        };
        unsigned long   Name;
        unsigned short    Id;
    };
    union {
        unsigned long   OffsetToData;
        struct {
            unsigned long   OffsetToDirectory:31;
            unsigned long   DataIsDirectory:1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    unsigned long   OffsetToData;
    unsigned long   Size;
    unsigned long   CodePage;
    unsigned long   Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

/* version stuff */

#define VS_FFI_SIGNATURE        0xFEEF04BDL

typedef struct tagVS_FIXEDFILEINFO
{
    unsigned long   dwSignature;            /* e.g. 0xfeef04bd */
    unsigned long   dwStrucVersion;         /* e.g. 0x00000042 = "0.42" */
    unsigned long   dwFileVersionMS;        /* e.g. 0x00030075 = "3.75" */
    unsigned long   dwFileVersionLS;        /* e.g. 0x00000031 = "0.31" */
    unsigned long   dwProductVersionMS;     /* e.g. 0x00030010 = "3.10" */
    unsigned long   dwProductVersionLS;     /* e.g. 0x00000031 = "0.31" */
    unsigned long   dwFileFlagsMask;        /* = 0x3F for version "0.42" */
    unsigned long   dwFileFlags;            /* e.g. VFF_DEBUG | VFF_PRERELEASE */
    unsigned long   dwFileOS;               /* e.g. VOS_DOS_WINDOWS16 */
    unsigned long   dwFileType;             /* e.g. VFT_DRIVER */
    unsigned long   dwFileSubtype;          /* e.g. VFT2_DRV_KEYBOARD */
    unsigned long   dwFileDateMS;           /* e.g. 0 */
    unsigned long   dwFileDateLS;           /* e.g. 0 */
} VS_FIXEDFILEINFO;

#endif

