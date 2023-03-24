/* Copyright (c) 2007 Robert ONeal <rob@rebelworks.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE. */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef WIN32
#   include <windows.h>
#else
#   include "pe_defines.h"
#endif

#include "pe_load.h"

static void pe_copy_sections(unsigned char *data, PIMAGE_NT_HEADERS ntheader, char *baseaddr);
static void pe_perform_base_reloc(char *baseaddr, PIMAGE_NT_HEADERS ntheader, unsigned long reloc_offset);


void *pe_load(char *filename){
    struct stat filestat;
    FILE *f;
    unsigned char *data;
    size_t size;

    char *baseaddr;

    unsigned long image_base;
    unsigned long reloc_offset;

    PIMAGE_DOS_HEADER dosheader;
    PIMAGE_NT_HEADERS ntheader;

    if(stat(filename, &filestat) < 0 )
    {
        return NULL;
    }

    f = fopen(filename, "rb");

    if(!f)
    {
        return NULL;
    }

    data = malloc(filestat.st_size);
    size = fread(data, 1, filestat.st_size, f);

    fclose(f);

    dosheader = (PIMAGE_DOS_HEADER) data;
    if (dosheader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    ntheader = (PIMAGE_NT_HEADERS) (data + dosheader->e_lfanew);
    if (ntheader->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    baseaddr = (char *)malloc(ntheader->OptionalHeader.SizeOfImage);
    memcpy(baseaddr, dosheader, dosheader->e_lfanew + ntheader->OptionalHeader.SizeOfHeaders);
    image_base = ntheader->OptionalHeader.ImageBase;
    pe_copy_sections(data, ntheader, baseaddr);
    reloc_offset = (unsigned long)(baseaddr - image_base);

    if(reloc_offset!=0) {
        pe_perform_base_reloc(baseaddr, ntheader, reloc_offset);
    }

    return (void*)baseaddr;
}

void pe_free(void *module)
{
    free(module);
}

PIMAGE_SECTION_HEADER pe_get_section(char *data, char *name)
{
    char *baseaddr;
    int i;
    PIMAGE_DOS_HEADER dosheader;
    PIMAGE_NT_HEADERS ntheader;
    PIMAGE_SECTION_HEADER section;

    baseaddr = (char *)data;

    dosheader = (PIMAGE_DOS_HEADER) baseaddr;
    ntheader = (PIMAGE_NT_HEADERS) (baseaddr + dosheader->e_lfanew);

    section = IMAGE_FIRST_SECTION(ntheader);
    for (i=0; i < ntheader->FileHeader.NumberOfSections; i++, section++)
    {
        if(!strcmp(section->Name, name))
        {
            return section;
        }
    }
    return NULL;
}

// internal stuff

static void pe_copy_sections(unsigned char *data, PIMAGE_NT_HEADERS ntheader, char *baseaddr)
{
    int i, size;
    char *dest;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntheader);
    for (i=0; i < ntheader->FileHeader.NumberOfSections; i++, section++)
    {
        if (section->SizeOfRawData == 0)
        {
            size = ntheader->OptionalHeader.SectionAlignment;
            if (size > 0)
            {
                dest = (char *)(baseaddr + section->VirtualAddress);
                section->Misc.PhysicalAddress = (unsigned long)dest;
                memset(dest, 0, size);
            }
        }else{
            dest = (char *)(baseaddr + section->VirtualAddress);
            memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);
            section->Misc.PhysicalAddress = (unsigned long)dest;
        }
    }
}

static void pe_perform_base_reloc(char *baseaddr, PIMAGE_NT_HEADERS ntheader, unsigned long reloc_offset)
{

    int i;

    PIMAGE_DATA_DIRECTORY directory;

    directory = (PIMAGE_DATA_DIRECTORY)&ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (directory->Size > 0)
    {
        PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(baseaddr + directory->VirtualAddress);
        for (; relocation->VirtualAddress > 0; )
        {
            unsigned char *dest = (unsigned char *)(baseaddr + relocation->VirtualAddress);
            unsigned short *reloc_info = (unsigned short *)((unsigned char *)relocation + IMAGE_SIZEOF_BASE_RELOCATION);
            for (i=0; i<((relocation->SizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, reloc_info++)
            {
                unsigned long *patch_addr;
                int type, offset;
                type = *reloc_info >> 12;
                offset = *reloc_info & 0xfff;
                if(type==IMAGE_REL_BASED_HIGHLOW){
                    patch_addr = (unsigned long *)(dest + offset);
                    *patch_addr += reloc_offset;
                }
            }

            relocation = (PIMAGE_BASE_RELOCATION)(((unsigned long)relocation) + relocation->SizeOfBlock);
        }
    }
}
