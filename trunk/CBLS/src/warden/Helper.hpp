#pragma once

#include "algos\sha1.h"
#include "algos\md5.h"

struct SHashList
{
	int		iCount;
	union
	{
		byte	abHashes[ 3 ][ SHA1_OUTPUT_SIZE ];
		byte	abBigHash[ SHA1_OUTPUT_SIZE * 3 ];
	};
};


void sha1_data( byte abHash[SHA1_OUTPUT_SIZE], const byte* pbcData, int iLen );
void sha1_string( sha1_state_s* psSHA1, const char* psczString );
void md5_string( md5_state_s* psMd5, const char* psczString );
void hash_list_update( SHashList* psHashList );
void hash_list_init( SHashList* psHashList, const byte* pbcInData, int iDataLen );
void hash_list_compute( SHashList* psHashList, byte* pbOutData, int iDataLen );
