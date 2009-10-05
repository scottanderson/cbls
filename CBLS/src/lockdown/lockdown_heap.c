/* Copyright (c) 2007 x86

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

#include <string.h>
#include "lockdown_heap.h"

t_lockdown_heap *ldheap_create()
{
	t_lockdown_heap *newheap = (t_lockdown_heap *) malloc(sizeof(t_lockdown_heap));
	newheap->memory = (char *)malloc(0x1000);
	newheap->currentlength = 0;
	newheap->maximumlength = 0x100;

	return newheap;
}

void ldheap_destroy(t_lockdown_heap *lockdown_heap)
{
	free(lockdown_heap->memory);
}

void ldheap_add(t_lockdown_heap *lockdown_heap, char *data)
{
	if(lockdown_heap->currentlength + 0x10 >= lockdown_heap->maximumlength)
	{
		lockdown_heap->maximumlength = lockdown_heap->maximumlength * 2;
		lockdown_heap->memory = (char *)realloc(lockdown_heap->memory, lockdown_heap->maximumlength * 0x10);
	}
	memcpy(lockdown_heap->memory + (lockdown_heap->currentlength * 0x10), data, 0x10);
	lockdown_heap->currentlength = lockdown_heap->currentlength + 1;
}

static int sortfunc(const void *record1, const void *record2)
{
	int *a = (int *) record1;
	int *b = (int *) record2;

	if(a[0] < b[0])
		return -1;
	else if(a[0] > b[0])
		return 1;

	return 0;
}

void ldheap_sort(t_lockdown_heap *lockdown_heap)
{
 	qsort(lockdown_heap->memory, lockdown_heap->currentlength, 0x10, sortfunc); 
}
