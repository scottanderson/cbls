#include "Stdafx.hpp"

#include "WardenLib.hpp"
#include "Packet.hpp"
	

//////////////////////////////////////////////////
//Function: DllMain
// Purpose: Dummy function in the default module.
//          Placeholder for use with more advanced modules.
//////////////////////////////////////////////////

int WINAPI DllMain( HINSTANCE hInst, DWORD dwMsg, LPVOID lpReserved )
{
	UNREFERENCED_PARAMETER( hInst );
	UNREFERENCED_PARAMETER( dwMsg );
	UNREFERENCED_PARAMETER( lpReserved );
	switch( dwMsg )
	{
	case DLL_PROCESS_ATTACH:
		return TRUE;
	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}
	return 0;
}