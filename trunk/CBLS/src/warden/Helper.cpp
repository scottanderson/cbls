#include "Stdafx.hpp"
#include "Helper.hpp"

//////////////////////////////////////////////////
//Function: sha1_data
//  Params: byte abHash[SHA1_OUTPUT_SIZE] (output hash)
//          const byte* pbcData (data to hash)
//          int iLen (length of pbcData)
//
// Purpose: Hashes data of a specified length with SHA-1
//          Hash result is returned.
//////////////////////////////////////////////////

void sha1_data( byte abHash[SHA1_OUTPUT_SIZE], const byte* pbcData, int iLen )
{
	sha1_state_s sSHA1;

	::sha1_init( &sSHA1 );
	::sha1_update( &sSHA1, pbcData, iLen );
	::sha1_finish( &sSHA1, abHash ); 
}

//////////////////////////////////////////////////
//Function: sha1_string
//  Params: sha1_state_s* psSHA1 (SHA-1 context)
//          const char* psczString (null terminated string)
//
// Purpose: Hashes a null terminated string with SHA-1
//          Hash context is updated.
//////////////////////////////////////////////////

void sha1_string( sha1_state_s* psSHA1, const char* psczString )
{
	const char* pszEnd = psczString;

	while ( 0 != *pszEnd ) pszEnd++;
	
	::sha1_update( psSHA1, (sha1_byte_t *)psczString, pszEnd - ( psczString + 1 ) );
	
	return;
}

//////////////////////////////////////////////////
//Function: md5_string
//  Params: md5_state_s* psMd5 (MD5 context)
//          const char* psczString (null terminated string)
//
// Purpose: Hashes a null terminated string with MD5
//          Hash context is updated.
//////////////////////////////////////////////////

void md5_string( md5_state_s* psMd5, const char* psczString )
{
	const char* pszEnd = psczString;

	while ( 0 != *pszEnd ) pszEnd++;	
	
	::md5_append( psMd5, (md5_byte_t *)psczString, pszEnd - ( psczString + 1 ) );
	
	return;
}

//////////////////////////////////////////////////
//Function: hash_list_update
//  Params: SHashList *psHashList (hash list structure)
//
// Purpose: A SHA-1 computation is performed to finalize HASH[ 0 ]
//          HASH[ 0 ] = UPDATE( HASH[ 1 ] ) UPDATE( HASH[ 0 ] ) UPDATE( HASH[ 2 ] ) 
//////////////////////////////////////////////////

void hash_list_update( SHashList *psHashList )
{
	sha1_state_s sSHA1;

	::sha1_init( &sSHA1 );
	
	::sha1_update( &sSHA1, psHashList->abHashes[ 1 ], SHA1_OUTPUT_SIZE );
	::sha1_update( &sSHA1, psHashList->abHashes[ 0 ], SHA1_OUTPUT_SIZE );
	::sha1_update( &sSHA1, psHashList->abHashes[ 2 ], SHA1_OUTPUT_SIZE );
	
	::sha1_finish( &sSHA1, psHashList->abHashes[ 0 ] ); 
	
	psHashList->iCount = 0;
	
	return;
}

//////////////////////////////////////////////////
//Function: hash_list_init
//  Params: SHashList *psHashList (hash list structure)
//          const byte* pbcInData (data to build our hashes)
//          int iDataLen          (length of data)
//
// Purpose: A SHA-1 computation is done with the first part of data to build HASH[ 1 ]
//          Another is done on the second half to build HASH[ 2 ]
//          HASH[ 0 ] value is zeroed.
//////////////////////////////////////////////////

void hash_list_init( SHashList *psHashList, const byte* pbcInData, int iDataLen )
{
	int iSizeHalf = iDataLen / 2;
	
	::sha1_data( psHashList->abHashes[ 1 ], pbcInData, iSizeHalf );
	::memset( psHashList->abHashes[ 0 ], 0, sizeof( psHashList->abHashes[ 0 ] ) );
	::sha1_data( psHashList->abHashes[ 2 ], &pbcInData[ iSizeHalf ], iSizeHalf );
	
	::hash_list_update( psHashList );
	
	return;
}


//////////////////////////////////////////////////
//Function: hash_list_compute
//  Params: SHashList *psHashList (hash list structure)
//          byte* pbOutData       (result hash data)
//          int iDataLen          (length of data)
//
// Purpose: Iteration is performed to copy data from HashList into
//          the result hash data, each time 014h bytes are copied(the size of one hash), hashes are recomputed.
//          This is done to avoid copying any repeated byte sequences.
//////////////////////////////////////////////////

void hash_list_compute( SHashList *psHashList, byte* pbOutData, int iDataLen )
{
	for ( int i = 0 ; i < iDataLen ; i++, psHashList->iCount++ )
	{
			if ( SHA1_OUTPUT_SIZE == psHashList->iCount )
			{
				::hash_list_update( psHashList );
			}
			pbOutData[ i ] = psHashList->abBigHash[ psHashList->iCount ];
	}
	return;
}
