#include "Stdafx.hpp"
#include "Packet.hpp"

CPacket::CPacket( byte* pbBuffer, int iSize )
{
	m_pbBuffer	= pbBuffer;
	m_iSize		= iSize;
	m_iIndex	= 0;
	return;
}

CPacket::~CPacket( void )
{
	return;
}

bool
CPacket::IsInBoundsEx( int iSize )
{
	if ( m_iSize - m_iIndex >= iSize )
	{
		return true;
	}
	m_iIndex = m_iSize + 1;

	return false;
}

bool
CPacket::IsInBounds( int iSize ) const
{
	return m_iSize - m_iIndex >= iSize ? true : false;
}	

bool
CPacket::GetPktSize( int* piSize ) const
{   // Gets packet size 'after' byte, +1 is to include byte.
	// [size][pkt]
	if ( false != IsInBounds( 1 ) )
	{
		*piSize = ( m_pbBuffer[ m_iIndex ] ) + 1;
		return true;
	}
	return false;
}

void
CPacket::GetData( byte* pbBuffer, int iLen )
{
	if ( false != IsInBoundsEx( iLen ) )
	{
		memcpy( pbBuffer, &m_pbBuffer[ m_iIndex ], iLen );
		m_iIndex += iLen;
	}
	return;
}

void
CPacket::PutData( byte* pbBuffer, int iLen )
{
	if ( false != IsInBoundsEx( iLen ) )
	{
		memcpy( &m_pbBuffer[ m_iIndex ], pbBuffer, iLen );
		m_iIndex += iLen;					
	}
	return;
}

void
CPacket::GetString( char* pszString, int iLen )
{ // pop len, get buffer
	byte bLength;

	*this > &bLength; //PktGetByte
	if ( false == IsInBoundsEx( iLen ) )
	{
		return;			
	}
	if ( iLen < bLength )
	{
		memcpy( pszString, &m_pbBuffer[ m_iIndex ], iLen );
		pszString[ bLength ] = 0;
		m_iIndex += bLength;
	}
	else
	{
		m_iIndex = m_iSize + 1;			
	}
	return;
}