#pragma once

class CPacket
{
public:
	CPacket( byte* pbBuffer, int iSize );
	~CPacket( void );

	bool GetPktSize( int* piSize ) const;

	void GetData( byte* pbBuffer, int iLen );
	void PutData( byte* pbBuffer, int iLen );

	void GetString( char* pszString, int iLen );
				
	bool	IsInBoundsEx( int iSize );
	bool	IsInBounds( int iSize ) const;

	bool	IsIndexSane( void ) const	{ return m_iIndex > m_iSize ? false : true; }

	int		GetIndex( void ) const		{ return m_iIndex; }
	int		GetSize( void ) const		{ return m_iSize; }
		
protected:
private:
	byte*	m_pbBuffer;
	int		m_iSize;
	int		m_iIndex;

public:
	//templates.
		template <typename T >
		void operator > ( T* t )
		{
			if ( false != IsInBoundsEx( sizeof( T ) ) )
			{
				*t = *( T* )&m_pbBuffer[ m_iIndex ];
				m_iIndex += sizeof( T );
			}
			return;
		}
		
		template <typename T >
		void operator < ( T* t )
		{
			if ( false != IsInBoundsEx( sizeof( T ) ) )
			{
				*( T* )&m_pbBuffer[ m_iIndex ] = *t;
				m_iIndex += sizeof( T );	
			}
			return;
		}
};