#pragma once

class CModule;

class CWardenLib
{
public:
	virtual int		Send( byte* pbData, int iSize );
	virtual bool	ModLoad( byte pbName[ 0x10 ], byte pbKey[ 0x10 ] );
	virtual void	ModSave( byte pbName[ 0x10 ], byte* pbData, int iModLen );
	virtual void*	Alloc( int iSize );
	virtual void	Free( void* pMem );
	virtual void	PutSession( const void* pData, int iSize );
	virtual bool	GetSession( void* pData, int* piSize );
		
	__declspec(dllexport)
		CModule* Export00( void );
		
protected:
private:
	struct SModInfo
	{
		void*	pBaseAddr;
		int		iLen;
		int		iDllCount;
	};

	CModule*	m_pcModule;
	SModInfo*	m_psModInfo[ 2 ];
	bool		m_yActiveMod; //either 1 or 0
	void*		m_pStoreData;
	int			m_iStoreSize;
};