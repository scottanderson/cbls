#include "Stdafx.hpp"
#include "ModRecv.hpp"

//////////////////////////////////////////////////
//Function: CModRecv::CModRecv (constructor)
//  Params: [in] byte pbName[ 0x10 ] ( module name )
//          [in] byte pbKey[ 0x10 ]  ( module key )
//          [in] int iSize           ( module size )
//
// Purpose: Call CModRecv::Init to setup the object.
//////////////////////////////////////////////////

CModRecv::CModRecv( byte pbName[ 0x10 ], byte pbKey[ 0x10 ], int iSize )
{
	Init( pbName, pbKey, iSize );
	return;
}

//////////////////////////////////////////////////
//Function: CModRecv::~CModRecv (deconstructor)
//
// Purpose: Nothing yet.
//////////////////////////////////////////////////

CModRecv::~CModRecv( void )
{
	return;
}

//////////////////////////////////////////////////
//Function: CModRecv::Reset
//
// Purpose: Call CModRecv::Init to reset the object.
//////////////////////////////////////////////////

void
CModRecv::Reset( void )
{
	Init( m_abName, m_abKey, m_iSize );
	
	return;
}

//////////////////////////////////////////////////
//Function: CModRecv::CompareSum
//
// Purpose: Finalizes a MD5 hash of the current received module
//          and compares it against the module name.
//////////////////////////////////////////////////

bool
CModRecv::CompareSum( void )
{
	byte abSum[ 0x10 ];

	::md5_finish( &m_sMd5, abSum );

	return 0 == ::memcmp( abSum, m_abName, sizeof( abSum ) );
}
	
//////////////////////////////////////////////////
//Function: CModRecv::Update
//  Params: [in] int iLen ( length of newly appended module data)
//
// Purpose: Updates the MD5 context with operator byte*
//          The index of the current recv module is moved to the end.
//////////////////////////////////////////////////

void
CModRecv::Update( int iLen )
{
	::md5_append( &m_sMd5, reinterpret_cast<const md5_byte_t*>(this), iLen );
	m_iIndex += iLen;

	return;
}

//////////////////////////////////////////////////
//Function: CModRecv::GetName
//  Params: [out] byte pbName[ 0x10 ] (buffer for the requested module name)
//
// Purpose: Copes the objects module name into the param.
//////////////////////////////////////////////////
		
void
CModRecv::GetName( byte pbName[ 0x10 ] )
{
	::memcpy( pbName, m_abName, sizeof( m_abName ) );

	return;
}
	
//////////////////////////////////////////////////
//Function: CModRecv::GetKey
//  Params: [out] byte pbName[ 0x10 ] (buffer for the requested module key)
//
// Purpose: Copes the objects module key into the param.
//////////////////////////////////////////////////

void
CModRecv::GetKey( byte pbKey[ 0x10 ] )
{
	::memcpy( pbKey, m_abKey, sizeof( m_abKey ) );
	
	return;
}

//////////////////////////////////////////////////
//Function: CModRecv::CheckBounds
//  Params: [in] int iSize ( additional size )
//
// Purpose: Checks to see if the additional size keeps the module inbounds if
//          appended onto the current index.       
//////////////////////////////////////////////////

bool
CModRecv::CheckBounds( int iSize )
{
	return iSize <= m_iSize - m_iIndex ? true : false;
}
	
//////////////////////////////////////////////////
//Function: CModRecv::IsDone
//
// Purpose: Checks to see if the data for incoming module has been completely written to.  
//////////////////////////////////////////////////

bool
CModRecv::IsDone( void )
{
	return m_iIndex < m_iSize ? false : true;
}

//////////////////////////////////////////////////
//Function: CModRecv::GetSize
//
// Purpose: Gets the original size of the module.
//////////////////////////////////////////////////

int
CModRecv::GetSize( void )
{
	return m_iSize;
}
		
//////////////////////////////////////////////////
//Function: CModRecv::GetData
//
// Purpose: Gets the data ptr to the base of the recv module.
//////////////////////////////////////////////////

byte*
CModRecv::GetData( void )
{
	return m_yModule;
}

//////////////////////////////////////////////////
//Function: CModRecv::GetData
//
// Purpose: Gets the data ptr to current end of the recv module.
//////////////////////////////////////////////////

CModRecv::operator byte*( void )
{
	return &m_yModule[ m_iIndex ];
}

//////////////////////////////////////////////////
//Function: CModRecv::Init
//
// Purpose: 
//////////////////////////////////////////////////

void
CModRecv::Init( byte pbName[ 0x10 ], byte pbKey[ 0x10 ], int iSize )
{
	::memcpy( m_abName, pbName, sizeof( m_abName ) );
	::memcpy( m_abKey, pbKey, sizeof( m_abKey ) );
			
	m_iSize		= iSize;
	m_iIndex	= 0;
			
	::md5_init( &m_sMd5 );
	
	return;
}

