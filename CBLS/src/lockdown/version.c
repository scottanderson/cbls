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

#ifdef WIN32
#   include <windows.h>
#else
#   include "pe_defines.h"
#endif

#include "pe_load.h"
#include "version.h"

int process_resource_directory(PIMAGE_RESOURCE_DIRECTORY res_start, PIMAGE_RESOURCE_DIRECTORY dir, char *baseaddr);
int process_resource_directory_entry(PIMAGE_RESOURCE_DIRECTORY res_start, PIMAGE_RESOURCE_DIRECTORY_ENTRY entry, char *baseaddr);

int pe_get_version(char *filename)
{
    int version;
    PIMAGE_SECTION_HEADER section;
    PIMAGE_RESOURCE_DIRECTORY resource;
    char *data = pe_load(filename);
    section = pe_get_section(data, ".rsrc");
    if(section){
        resource = (PIMAGE_RESOURCE_DIRECTORY)(data + section->VirtualAddress);
        version = process_resource_directory(resource, resource, data);
        if(version!=0)
        {
            return version;
        }
    }else{
        return 0;
    }

    return 0;
}

int process_resource_directory_entry(PIMAGE_RESOURCE_DIRECTORY res_start, PIMAGE_RESOURCE_DIRECTORY_ENTRY entry, char *baseaddr)
{
    PIMAGE_RESOURCE_DATA_ENTRY data;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY v_entry;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY v_entry2;
    PIMAGE_RESOURCE_DIRECTORY v_dir;
    VS_FIXEDFILEINFO *v_info;
    int version = 0;
    if(entry->Id == 0x10)
    {
        if(entry->DataIsDirectory)
        {
            v_dir = (PIMAGE_RESOURCE_DIRECTORY)((char *)res_start + entry->OffsetToDirectory);
            v_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(v_dir + 1);
            if(v_entry->DataIsDirectory)
            {
                v_dir = (PIMAGE_RESOURCE_DIRECTORY)((char *)res_start + v_entry->OffsetToDirectory);
                v_entry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(v_dir + 1);
                data = (PIMAGE_RESOURCE_DATA_ENTRY)((char *)res_start + v_entry2->OffsetToData);
                v_info = (VS_FIXEDFILEINFO *)(baseaddr + (data->OffsetToData + 40));

                version = (((v_info->dwProductVersionMS >> 16) & 0xFF) << 24)
                    | (((v_info->dwProductVersionMS & 0xFFFF) & 0xFF) << 16)
                    | (((v_info->dwProductVersionLS >> 16) & 0xFF) << 8)
                    | ((v_info->dwProductVersionLS & 0xFFFF) & 0xFF);

                return version;
            }
        }
    }

    if (entry->DataIsDirectory) {
        version = process_resource_directory(res_start, (void *)((char *)res_start + entry->OffsetToDirectory), baseaddr);
    }

    return version;
}


int process_resource_directory(PIMAGE_RESOURCE_DIRECTORY res_start, PIMAGE_RESOURCE_DIRECTORY dir, char *baseaddr)
{
    PIMAGE_RESOURCE_DIRECTORY_ENTRY entry = (void *)(dir + 1);
    int i, version;
    for (i = 0; i < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; i++, entry++)
    {
        version = process_resource_directory_entry(res_start, entry, baseaddr);
        if(version!=0)
        {
            return version;
        }
    }
    return 0;
}
