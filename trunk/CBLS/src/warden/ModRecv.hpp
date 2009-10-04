#pragma once

#include "algos\md5.h"

class CModRecv
{
public:	
	CModRecv( byte pbName[ 0x10 ], byte pbKey[ 0x10 ], int iSize );
	~CModRecv( void );
		
	void Reset( void );
	
	bool CompareSum( void );
		
	void Update( int iLen );
		
	void GetName( byte pbName[ 0x10 ] );
	void GetKey( byte pbKey[ 0x10 ] );
		
	bool CheckBounds( int iSize );
	
	bool	IsDone( void );

	int		GetSize( void );
	byte*	GetData( void );

	operator byte*( void );
		
protected:
private:
	void Init( byte pbName[ 0x10 ], byte pbKey[ 0x10 ], int iSize );
		
	byte			m_abName[ 0x10 ];
	byte			m_abKey[ 0x10 ];
	md5_state_s		m_sMd5;
	int				m_iSize;
	int				m_iIndex;
	byte			( m_yModule )[];
};