/*
 * RC4Crypto.cpp
 *
 *  Created on: Sep 14, 2009
 *      Author: Jeffrey Shorf (jeffrey.shorf@gmail.com)
 */

#include "RC4Crypto.h"
#include <string.h>

RC4Crypto::RC4Crypto(unsigned char* base) {
	char val = 0;
	int i;
	int position;
	char temp;

	RC4Crypto::key = new unsigned char[0x102];

	for (i = 0; i < 0x100; i++)
		key[i] = (char)i;

	for (i = 1; i <= 0x40; i++)
	{
		val += key[(i * 4) - 4] + base[position++ % strlen((char*)base)];
		//val += strlen(base);
	}
}
