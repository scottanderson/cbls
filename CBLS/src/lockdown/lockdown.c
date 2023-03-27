/*
Copyright (c) 2007 Robert ONeal <rob@rebelworks.com>
Copyright (c) 2007 x86

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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#   include <windows.h>
#else
#   include "pe_defines.h"
#endif

#include "version.h"
#include "pe_load.h"

#include "lockdown.h"
#include "lockdown_heap.h"
#include "lockdown_sha1.h"

int seeds[20] =
{
     0xA1F3055A ,   //00
     0x5657124C ,   //01
     0x1780AB47 ,   //02
     0x80B3A410 ,   //03
     0xAF2179EA ,   //04
     0x0837B808 ,   //05
     0x6F2516C6 ,   //06
     0xE3178148 ,   //07
     0x0FCF90B6 ,   //08
     0xF2F09516 ,   //09
     0x378D8D8C ,   //10
     0x07F8E083 ,   //11
     0xB0EE9741 ,   //12
     0x7923C9AF ,   //13
     0xCA11A05E ,   //14
     0xD723C016 ,   //15
     0xFD545590 ,   //16
     0xFB600C2E ,   //17
     0x684C8785 ,   //18
     0x58BEDE0B ,   //19
};

static int shuffle_value_string(char *str, int len, char *buffer);
static int hash_file(LD_SHA1_CTX *ctx, char *filename, int seed);
static int process_reloc_dir(t_lockdown_heap *lockdown_heap, char *baseaddr, PIMAGE_DATA_DIRECTORY reloc);
static int process_section(LD_SHA1_CTX *ctx, t_lockdown_heap *lockdown_heap, char *baseaddr, void *preferred_baseaddr, PIMAGE_SECTION_HEADER section, int section_alignment, int seed);
static int calculate_digest(char *str1, int *length, char *str2);
static void word_shifter(unsigned short *str1, unsigned short *str2);

int get_digit(char *filename)
{
    int digit_1, digit_2;
    char *digit_ptr = (char*)filename + (strlen(filename) - 4);
    if(!digit_ptr)
        return 0;

    digit_1 = (int)(*(digit_ptr - 1) - '0');
    digit_2 = (int)(*(digit_ptr - 2) - '0');

    if(digit_2 == 1)
        digit_1 += 10;
    if(digit_1 < 0 || digit_1 > 19)
        return 0;

    return digit_1;
}

int ldCheckRevision(char *path_file1, char *path_file2, char *path_file3, char *valuestring, uint32_t *version, uint32_t *checksum, char digest[0x11], char *lockdownfile, char *imagedump)
{
    LD_SHA1_CTX ctx;
    int return_is_valid = 1, module_offset = 0, seed, i;
    char ld_sha1_out_buffer_1[0x14], ld_sha1_out_buffer_2[0x14];
    int length_valuestring = (int)strlen(valuestring);
    char valuestring_encoded[0x10];
    char valuestring_buffer_1[0x40], valuestring_buffer_2[0x40];
    char temp_memory[0x10];
    int digit = get_digit(lockdownfile);

    pe_get_version(path_file1);

    seed = seeds[digit];

    if(!shuffle_value_string(valuestring, length_valuestring, valuestring_encoded))
    {
        return 0;
    }

    memset(valuestring_buffer_1, 0x36, 0x40);
    memset(valuestring_buffer_2, 0x5c, 0x40);

    for(i = 0; i < 0x10; i++)
    {
        valuestring_buffer_1[i] = valuestring_buffer_1[i] ^ valuestring_encoded[i];
        valuestring_buffer_2[i] = valuestring_buffer_2[i] ^ valuestring_encoded[i];
    }

    ld_sha1_init(&ctx);
    ld_sha1_update(&ctx, valuestring_buffer_1, 0x40);

    if(!hash_file(&ctx, lockdownfile, seed))
    {
        return 0;
    }
    if(!hash_file(&ctx, path_file1, seed))
    {
        return 0;
    }
    if(!hash_file(&ctx, path_file2, seed))
    {
        return 0;
    }
    if(!hash_file(&ctx, path_file3, seed))
    {
        return 0;
    }

    ld_sha1_hash_file(&ctx, imagedump);

    ld_sha1_update(&ctx, (char*)&return_is_valid, 4); /* Used to verify return address */
    ld_sha1_update(&ctx, (char*)&module_offset, 4); /* Used to verify the module */

    ld_sha1_final(&ctx, (int*)ld_sha1_out_buffer_1);

    ld_sha1_init(&ctx);
    ld_sha1_update(&ctx, (char*)valuestring_buffer_2, 0x40);
    ld_sha1_update(&ctx, (char*)ld_sha1_out_buffer_1, 0x14);
    ld_sha1_final(&ctx, (int*)ld_sha1_out_buffer_2);

    memmove(checksum, ld_sha1_out_buffer_2, 4);
    memmove(temp_memory, ld_sha1_out_buffer_2 + 4, 0x10);

    length_valuestring = 0xFF;
    if(!calculate_digest(digest, &length_valuestring, temp_memory))
    {
        return 0;
    }

    digest[length_valuestring] = 0x00;

    *version = pe_get_version(path_file1);
    return 1;
}

int shuffle_value_string(char *str, int len, char *buffer)
{
    int pos;
    int i;
    unsigned char adder;
    unsigned char shifter;

    pos = 0;

    while(len)
    {
        shifter = 0;

        for(i = 0; i < pos; i++)
        {
            unsigned char b = buffer[i];
            buffer[i] = -buffer[i] + shifter;
            shifter = ((((b << 8) - b) + shifter) >> 8);
        }

        if(shifter)
        {
            if(pos >= 0x10)
                return 0;

            buffer[pos++] = shifter;
        }

        adder = str[len - 1] - 1;
        for(i = 0; i < pos && adder; i++)
        {
            buffer[i] = buffer[i] + adder;
            adder = buffer[i] < adder;
        }

        if(adder)
        {
            if(pos >= 0x10)
                return 0;

            buffer[pos++] = adder;
        }

        len--;
    }

    memset(buffer + pos, 0, 0x10 - pos);

    return 1;
}


int hash_file(LD_SHA1_CTX *ctx, char *filename, int seed)
{
    int i, headers_size, sectionalignment;
    void *imagebase, *module;
    char *first_section, *baseaddr;

    PIMAGE_DATA_DIRECTORY import_dir, reloc_dir;
    PIMAGE_DOS_HEADER dosheader;
    PIMAGE_NT_HEADERS ntheader;

    t_lockdown_heap *lockdown_heap = ldheap_create();

    module = pe_load(filename);
    if(!module)
    {
        ldheap_destroy(lockdown_heap);
        return 0;
    }

    baseaddr = (char*)module;

    dosheader = (PIMAGE_DOS_HEADER) baseaddr;
    ntheader = (PIMAGE_NT_HEADERS) (baseaddr + dosheader->e_lfanew);

    if(ntheader->Signature != IMAGE_NT_SIGNATURE)
    {
        pe_free(module);
        ldheap_destroy(lockdown_heap);
        return 0;
    }

    sectionalignment = ntheader->OptionalHeader.SectionAlignment;
    imagebase = (void*) ntheader->OptionalHeader.ImageBase;

    import_dir = (PIMAGE_DATA_DIRECTORY)&ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    reloc_dir = (PIMAGE_DATA_DIRECTORY)&ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    first_section = (char *)IMAGE_FIRST_SECTION(ntheader);

    headers_size = ntheader->OptionalHeader.SizeOfHeaders;
    ld_sha1_update(ctx, baseaddr, headers_size);

    if(reloc_dir->VirtualAddress && reloc_dir->Size != 0)
    {
        if(!process_reloc_dir(lockdown_heap, baseaddr, reloc_dir))
        {
            pe_free(module);
            ldheap_destroy(lockdown_heap);
            return 0;
        }
    }

    for(i = 0; i < (ntheader->FileHeader.NumberOfSections); i++)
    {
        if(!process_section(ctx, lockdown_heap, baseaddr, imagebase, (PIMAGE_SECTION_HEADER)(first_section + (i * 0x28)), sectionalignment, seed))
        {
            pe_free(module);
            ldheap_destroy(lockdown_heap);
            return 0;
        }
    }

    ldheap_destroy(lockdown_heap);

    pe_free(module);

    return 1;
}

int process_reloc_dir(t_lockdown_heap *lockdown_heap, char *baseaddr, PIMAGE_DATA_DIRECTORY reloc)
{
    int i, edx, data[4];
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(baseaddr + reloc->VirtualAddress);
    for (; relocation->VirtualAddress > 0; )
        {
            short *reloc_info = (short *)((char *)relocation + IMAGE_SIZEOF_BASE_RELOCATION);
            for (i=0; i<((relocation->SizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, reloc_info++)
            {
                int type, offset;
                type = *reloc_info >> 12;
                offset = *reloc_info & 0xfff;
                if(type != 0)
                {
                    switch (type)
                    {
                        case IMAGE_REL_BASED_LOW:
                            edx = 2;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            edx = 4;
                            break;
#ifdef _WIN64
                        case IMAGE_REL_BASED_DIR64:
                            edx = 8;
                            break;
#endif
                        default:
                            return 0;
                    }
                    data[0] = relocation->VirtualAddress + offset;
                    data[1] = edx;
                    data[2] = 2;
                    data[3] = type;
                    ldheap_add(lockdown_heap, (char*)data);
                }
            }
            relocation = (PIMAGE_BASE_RELOCATION)(((char *)relocation) + relocation->SizeOfBlock);
        }
    return 1;
}

int process_section(LD_SHA1_CTX *ctx, t_lockdown_heap *lockdown_heap, char *baseaddr, void *preferred_baseaddr, PIMAGE_SECTION_HEADER section, int section_alignment, int seed)
{
    int eax, virtual_addr, virtual_size, value;
    int index, bytes;
    int i;
    int *lockdown_memory = (int*) lockdown_heap->memory; /* Lets us address the memory as an int, which cleans up a lot of code. */
    char *allocated_memory_base;
    int lower_offset = (uintptr_t)baseaddr - (uintptr_t)preferred_baseaddr;

    virtual_addr = section->VirtualAddress;
    virtual_size = section->Misc.VirtualSize;

    bytes = ((virtual_size + section_alignment - 1) & ~(section_alignment - 1)) - virtual_size;

    if((int)section->Characteristics < 0)
    {
        ld_sha1_pad(ctx, bytes + virtual_size);
    }
    else
    {
        index = 0;
        if(lockdown_heap->currentlength > 0)
        {
            for(i = 0; index < lockdown_heap->currentlength && lockdown_memory[i] < virtual_addr; i += 4)
            {
                index++;
            }
        }
        if(virtual_size > 0)
        {
            char *starting_memory = baseaddr + virtual_addr;
            char *ptr_memory = baseaddr + virtual_addr;
            int memory_offset = index * 4;
            do
            {
                int section_length = starting_memory - ptr_memory + virtual_size;
                eax = 0;
                if(index < lockdown_heap->currentlength)
                {
                    eax = (uintptr_t)(lockdown_memory[memory_offset] + starting_memory - virtual_addr);
                }
                if(eax)
                {
                    eax = eax - (uintptr_t)ptr_memory;
                    if(eax < section_length)
                    {
                        section_length = eax;
                    }
                }
                if(section_length)
                {
                    ld_sha1_update(ctx, ptr_memory, section_length);
                    ptr_memory = ptr_memory + section_length;
                }
                else
                {
                    int heap_buffer[0x10];
                    memcpy(heap_buffer, lockdown_memory + memory_offset, 0x10);
                    value = (*(int*)ptr_memory - lower_offset) ^ seed;
                    ld_sha1_update(ctx, (char*)&value, 4);
                    ptr_memory = ptr_memory + heap_buffer[1];
                    index = index + 1;
                    memory_offset += 4;
                }
            } while((ptr_memory - starting_memory) < virtual_size);
        }

        if(bytes > 0)
        {
            int i = 0;
            allocated_memory_base = (char*) malloc(bytes);
            memset(allocated_memory_base, 0, bytes);
            do
            {
                eax = 0;
                if(index < lockdown_heap->currentlength)
                {
                    value = *(int*)(lockdown_heap->memory + (index * 16));
                    eax = (uintptr_t)(value - virtual_size - virtual_addr + allocated_memory_base);
                }
                bytes += i;
                if(eax)
                {
                    eax = eax - ((int*)allocated_memory_base)[i / 4];
                    if(eax < bytes)
                    {
                        bytes = eax;
                    }
                }
                if(bytes)
                {
                    ld_sha1_update(ctx, &allocated_memory_base[i], bytes);
                    i += bytes;
                }
            } while(i < bytes);
            free(allocated_memory_base);
        }
    }
    return 1;
}

int calculate_digest(char *str1, int *length, char *str2)
{
    int i, j;
    unsigned short word1, word2;
    char *ptr_str1 = str1;
    int ret = 1;

    for(i = 0x10; i > 0; )
    {
        /* Skips over null bytes. */
        while(i && !str2[i - 1])
        {
            i--;
        }
        if(i)
        {
            word1 = 0;
            for(j = i - 1; j >= 0; j--)
            {
                word2 = (word1 << 8) + (str2[j] & 0xFF);
                word_shifter(&word2, &word1);
                str2[j] = (char) word2;
            }
            if((0x10 - i) >= *length)
            {
                ret = 0;
            }
            else
            {
                ptr_str1[0] = word1 + 1;
            }
            ptr_str1++;
        }
    }
    *length = ptr_str1 - str1;
    return ret;
}

void word_shifter(unsigned short *str1, unsigned short *str2)
{
    *str2 = (((*str1 >> 8) + (*str1 & 0xFF)) >> 8) + ((((*str1 >> 8) + (*str1 & 0xFF)) & 0xFF));
    *str2 = (*str2 & 0xFFFFFF00) | (((*str2 + 1) & 0xFF) - (((*str2 & 0xFF) != 0xFF) ? 1 : 0));

    *str1 = ((*str1 - *str2) & 0xFFFF00FF) | (((((*str1 - *str2) >> 8) & 0xFF) + 1) ? 0 : 0x100);
    *str1 = (*str1 & 0xFFFFFF00) | (-*str1 & 0x000000FF);
}

