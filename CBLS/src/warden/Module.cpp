#include "Stdafx.hpp"
#include "Module.hpp"

#include "Helper.hpp"

//////////////////////////////////////////////////
//Function: operator new
// Purpose: Overload the default new operator, 
//          using the games internal heap instead of CRT.
//////////////////////////////////////////////////

inline void * __cdecl operator new( unsigned int iSize, CWardenLib* pcWardLib )
{
	return pcWardLib->Alloc( iSize );
}

// note: for exceptions only.
inline void __cdecl operator delete( void *pMem, CWardenLib* pcWardLib )
{
	pcWardLib->Free( pMem );
	return;
}

//////////////////////////////////////////////////
//Function: operator new
// Purpose: Overload the default new operator,
//          with extra param, to handle CModRecv (to avoid fragmentation).
//   Notes: This is only used for CModRecv in the default module.
//////////////////////////////////////////////////

inline void * __cdecl operator new( unsigned int iSize, CWardenLib* pcWardLib, int iExtraSize )
{
	return pcWardLib->Alloc( iSize + iExtraSize );
}

// note: for exceptions only.
inline void __cdecl operator delete( void *pMem, CWardenLib* pcWardLib, int iExtraSize )
{
	UNREFERENCED_PARAMETER( iExtraSize );

	pcWardLib->Free( pMem );
	return;
}


//////////////////////////////////////////////////
//Function: CModule::CModule (constructor)
//  Params: [in] CWardenLib* (WardenClient Library for modules) 
// Purpose: Clear the download module pointer and current decrypted data stream position.
//          Finally save the warden library(from game) to the class.
//////////////////////////////////////////////////

CModule::CModule( CWardenLib* pcWardLib )
{
	m_pcModRecv = NULL;
	m_sCryptState.m_iCryptPos  = 0;
	
	m_pcWardLib = pcWardLib;
	return;
}

//////////////////////////////////////////////////
//Function: CModule::~CModule (deconstructor)
// Purpose: Don't do anything
//////////////////////////////////////////////////

CModule::~CModule( void )
{
	return;
}

//////////////////////////////////////////////////
//Function: CModule::Init (virtual pointer, called by WardenClient)
//  Params: [in] const byte* pKey (our session key)
//          [in] int iKeyLen      (session key length)
//
// Purpose: Attempt to extract a previous session using GetSession,
//          if unable to find a previous session or one of the same size,
//          then build a brand new one with our own defined module algorithm.
//////////////////////////////////////////////////

void
CModule::Init( const byte* pKey, int iKeyLen )
{
	SHashList sHashList;
	byte yRC4Secret[ 0x10 ];
	int iModDataLen = sizeof( m_sCryptState );
	
	if ( false == m_pcWardLib->GetSession( &m_sCryptState, &iModDataLen ) ||
		   iModDataLen != sizeof( m_sCryptState ) )
	{
		hash_list_init( &sHashList, pKey, iKeyLen );
		hash_list_compute( &sHashList, yRC4Secret, sizeof( yRC4Secret ) );
		rc4_init( &m_sCryptState.m_sRC4SendKey, yRC4Secret, sizeof( yRC4Secret ) );
		hash_list_compute( &sHashList, yRC4Secret, sizeof( yRC4Secret ) );
		rc4_init( &m_sCryptState.m_sRC4RecvKey, yRC4Secret, sizeof( yRC4Secret ) );
		
		m_sCryptState.m_iCryptPos = 0;
			
	}
	
	return;
}

//////////////////////////////////////////////////
//Function: CModule::Cleanup (virtual pointer, called by WardenClient)
// Purpose: See if a CRecvMod object exists, if it does clean it up.
//          Next store the current session into WardenClient and free the module class from memory.
//////////////////////////////////////////////////

void
CModule::Cleanup( void )
{
// TODO: Translated incorrectly, fix for OOP/D.

	if ( NULL != m_pcModRecv )
	{
		m_pcModRecv->~CModRecv( );
		operator delete( (void*)m_pcModRecv, m_pcWardLib );
		m_pcModRecv = NULL;		
	}
	
	m_pcWardLib->PutSession( &m_sCryptState, sizeof( m_sCryptState ) );
	
	m_pcWardLib->Free( this );
	return;
}

//////////////////////////////////////////////////
//Function: CModule::ParsePacket (virtual pointer, called by WardenClient)
//  Params: [in/out] byte* lpPacket (encrypted contents)
//          [in]     int iLength    (length of packet)
//          [out]    int& riRead    (how much read this call)
//
// Purpose: First check previous read length is in bounds, if it is find current position into lpPacket
//          and continue stream decryption, then build a Packet object. Handle all the opcodes
//          until there is error or run out of packet data.
//////////////////////////////////////////////////

bool
CModule::ParsePacket( byte* lpPacket, int iLength, int& riRead )
{
	typedef int ( CModule:: *func_opcodes ) ( CPacket* );
	
	static func_opcodes pf_opcodes[ ] = { &CModule::OpModLoadCache,
										  &CModule::OpModDownLoad,
										  &CModule::OpTest };
	
	int iCryptPos = m_sCryptState.m_iCryptPos;
	int iReadLen = iLength - iCryptPos;
	
	if ( 0 <= iReadLen && iReadLen <= iLength )
	{
		rc4_crypt( &m_sCryptState.m_sRC4RecvKey, &lpPacket[ iCryptPos ], iReadLen );
		m_sCryptState.m_iCryptPos = iLength;
		riRead = 0;
		
		CPacket cPkt( lpPacket, iLength );
		if ( iLength >= 1 )
		{
			int iResult;
			do
			{
				byte bOpCode;
				cPkt > &bOpCode;
				if ( bOpCode >= sizeof( pf_opcodes ) / sizeof( pf_opcodes[ 0 ] ) ) return false;
									
				iResult = ( this->*pf_opcodes[ bOpCode ] )( &cPkt );
			
				if ( iResult == OS_ERROR ) return false;
				if ( iResult == OS_NIB ) return true;
			
				int iDiff = cPkt.GetIndex( ) - riRead;
				m_sCryptState.m_iCryptPos -= iDiff;
				riRead += iDiff;
				
			} while ( iResult != OS_EXT && false != cPkt.IsInBounds( 1 ) );
		}
		return true;			
	}
	return false;
}

//////////////////////////////////////////////////
//Function: CModule::Frame (virtual pointer, called by WardenClient)
//  Params: [in] int iSync (time since last frame)
//
// Purpose: Called every game frame, handles persistent calculations that cannot be computed
//          atomicly by any other callback.
//////////////////////////////////////////////////
void
CModule::Frame( int iSync )
{
	UNREFERENCED_PARAMETER( iSync );

	return;
}


//////////////////////////////////////////////////
//Function: CModule::OpModLoadCache (a primary module opcode)
//  Params: [in] CPacket* pcPkt (packet object)
//
//  Packet: ModName[0x10]ModKey[0x10]ModSize[0x04]
//
// Purpose: Attempt to load a new module from the game cache, using the WardenClient library.
//          Success send true(01h), preprared to switch context to new module.
//          Failure send false(00h), needs new module.
//          Any malformed packets will cause the default module to die. OS_ERROR
//          On failure setup a CModRecv object in wait for the pending new module. 
//////////////////////////////////////////////////
int
CModule::OpModLoadCache( CPacket* pcPkt )
{
	byte abModuleName[ 0x10 ];
	byte abModuleKey[ 0x10 ];
	int iModuleSize;
		
	if ( false == pcPkt->IsInBounds( sizeof( abModuleName ) + sizeof( abModuleKey ) + sizeof( int ) ) )
	{
		return OS_NIB;
	}
	 	
	pcPkt->GetData( abModuleName, sizeof( abModuleName ) );
	pcPkt->GetData( abModuleKey, sizeof( abModuleKey ) );
	*pcPkt > &iModuleSize;
	 	
	// Poor OOP/D, implemented so ASM mirrors C++ counterpart.
	if ( false == pcPkt->IsIndexSane( ) )
	{
		return OS_ERROR;
	}
	 	
	if ( NULL != m_pcModRecv )
	{
		m_pcModRecv->~CModRecv( );
		operator delete( (void*) m_pcModRecv, m_pcWardLib );

		m_pcModRecv = NULL;
	}
	 	
	if ( false != m_pcWardLib->ModLoad( abModuleName, abModuleKey ) )
	{ // Module loaded ok.
		byte bResponce = true;
		CryptSend( &bResponce, sizeof( bResponce ) );
		return OS_EXT;
	}
	 		
	m_pcModRecv = new( m_pcWardLib, iModuleSize ) CModRecv( abModuleName, abModuleKey, iModuleSize );
	 	
	byte bResponce = false;
	CryptSend( &bResponce, sizeof( bResponce ) );
	 	
	return OS_OK;
}

//////////////////////////////////////////////////
//Function: CModule::OpModDownLoad (a primary module opcode)
//  Params: [in] CPacket* pcPkt (packet object)
//
//  Packet: BufferSize[0x02]Buffer[...]
//
// Purpose: This is reached if OpModLoadCache fails.
//          New module is downloaded and added to the game cache using WardenLibrary.
//          Stream incoming data to ModRecv class until the size specified by OpModLoadCache is reached.
//          Once reached compare the module data md5sum to the module name.
//          If the name of the new module(being also the md5 of its data) is the same the new module data,
//          it will be written to cache and success(01h) is sent, otherwise failure(00h) is sent and the mod data is reset.
//////////////////////////////////////////////////
int
CModule::OpModDownLoad( CPacket* pcPkt )
{
	word wBufferSize;
	  
	if ( NULL == m_pcModRecv )
	{
		return OS_ERROR;
	}
	 	
	if ( false == pcPkt->IsInBounds( sizeof( wBufferSize ) ) )
	{	
		return OS_NIB;
	}
	 	
	*pcPkt > &wBufferSize;
	 	
	if ( false == pcPkt->IsInBounds( wBufferSize ) )
	{
		return OS_NIB;
	}
	 	
	if ( false == m_pcModRecv->CheckBounds( wBufferSize ) )
	{
		return OS_ERROR;			
	}
	 	
	pcPkt->GetData( *m_pcModRecv, wBufferSize );
	m_pcModRecv->Update( wBufferSize );
	 	
	if ( false != m_pcModRecv->IsDone( ) )
	{
		if ( false != m_pcModRecv->CompareSum( ) )
		{ 		
			byte abModName[ 0x10 ];
			byte abModKey[ 0x10 ];
	 	  	
			m_pcModRecv->GetName( abModName );
			m_pcModRecv->GetKey( abModKey );
	 	  	
			m_pcWardLib->ModSave( abModName, m_pcModRecv->GetData( ), m_pcModRecv->GetSize( ) );
	 	  	
			m_pcModRecv->~CModRecv( );
			operator delete( (void*) m_pcModRecv, m_pcWardLib );

			m_pcModRecv = NULL;
	 	  	
			if ( false == m_pcWardLib->ModLoad( abModName, abModKey ) )
			{
				return OS_ERROR;
			}
			byte bResponce = 1;
			CryptSend( &bResponce, sizeof( bResponce ) );
			return OS_EXT;
		}
		else
		{
			m_pcModRecv->Reset( );
			byte bResponce = 0;
			CryptSend( &bResponce, sizeof( bResponce ) );
		}
	}
	return OS_OK;
}

//////////////////////////////////////////////////
//Function: CModule::OpTest (a primary module opcode)
//  Params: [in] CPacket* pcPkt (packet object)
//
//  Packet: Len[0x01]String[0xFF]
//
// Purpose: Module sanity test on hash functions.
//          Does SHA-1 and MD5 computations on String[size 0FFh]
//          Both the SHA-1 sum and MD5 sum are sent back the server for verification.
//            
//////////////////////////////////////////////////
int
CModule::OpTest( CPacket* pcPkt )
{
	int iLen;
	char szString[ 0xFF ];
	byte abPacket[ SHA1_OUTPUT_SIZE + MD5_DIGEST_SIZE + 0x01 ];
	byte abSHA1[ SHA1_OUTPUT_SIZE ], abMD5[ MD5_DIGEST_SIZE ];
	  
	if ( false == pcPkt->GetPktSize( &iLen ) || false == pcPkt->IsInBounds( iLen ) )
	{
		return OS_NIB; 		
	}
	
	pcPkt->GetString( szString, sizeof( szString ) );

	if ( false == pcPkt->IsIndexSane( ) )
	{
		return OS_ERROR; 			
	}
	
	CPacket cPkt( abPacket, sizeof( abPacket ) );	 	
	sha1_state_s sSHA1;

	sha1_init( &sSHA1 );
	sha1_string( &sSHA1, szString );
	sha1_finish( &sSHA1, abSHA1 );
	 	
	md5_state_s sMd5;
	
	md5_init( &sMd5 );
	md5_string( &sMd5, szString );
	md5_finish( &sMd5, abMD5 );
	 	
	byte bOpCode = 2;
	cPkt < &bOpCode;
	cPkt.PutData( abSHA1, sizeof( abSHA1 ) );
	cPkt.PutData( abMD5, sizeof( abMD5 ) );
	CryptSend( abPacket, cPkt.GetIndex( ) ); // TODO: This C++ implementation breaks encapsulation.

	return OS_OK;
}
	


//////////////////////////////////////////////////
//Function: CWardenLib::Export00 (module entry point)
// Purpose: Module entry point.
//          Allocate our CModule object and return it to CWardenLib  
//////////////////////////////////////////////////

__declspec(dllexport)
CModule*
CWardenLib::Export00( void )
{
	CModule* pcMod =  new( this ) CModule( this );
	return pcMod;
}