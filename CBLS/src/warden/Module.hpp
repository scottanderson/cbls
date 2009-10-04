#pragma once

#include "WardenLib.hpp"
#include "Packet.hpp"
#include "ModRecv.hpp"

#include "algos\rc4.h"

class CModule
{
public:
	CModule( CWardenLib* pcWardLib );
	~CModule( void );
	virtual void Init( const byte* pKey, int iKeyLen );
	virtual void Cleanup( void );
	virtual bool ParsePacket( byte* lpPacket, int iLength, int& riRead );
	virtual void Frame( int iFrame );
protected:
	CWardenLib*	m_pcWardLib;
	CModRecv*	m_pcModRecv;
	
	struct SCryptState
	{
		rc4_state		m_sRC4SendKey;
		rc4_state		m_sRC4RecvKey;
		int				m_iCryptPos;
	} m_sCryptState;

private:	
	enum
	{ // opcode status.
		OS_OK = 0,	// success, nothing to say.
		OS_EXT,			// success, leave mod soon as possible
		OS_NIB,			// failure, not in bounds ( ~OOB )
		OS_ERROR,		// failure, can't recover.
	};
	int OpModLoadCache( CPacket* );
	int OpModDownLoad( CPacket* );
	int OpTest( CPacket* );
	
//	int opcode_mod_cache_load( CPkt* );
//	int opcode_mod_down_load( CPkt* );
//	int opcode_unknown( CPkt* );
	
	int CryptSend( byte* pbPacket, int iSize )
	{
		rc4_crypt( &m_sCryptState.m_sRC4SendKey, pbPacket, iSize );
		return m_pcWardLib->Send( pbPacket, iSize );
	}
	
	/*
	version a
	inline void __cdecl operator delete ( void *p )
	{
		( ( CModule* ) p )->m_pcWardLib->Free( p );
	}*/
	
};