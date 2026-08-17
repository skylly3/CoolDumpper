// cooldebug.cpp : Defines the initialization routines for the DLL.
//
#include "stdafx.h"
#include "cooldebug.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//初始化--API
extern "C" void WINAPI InitPlugin(HWND hWnd)
{
	g_hWndList = hWnd;
	TellUnpacker(g_szInitOk);
	HWND hWndDebug = ::GetDlgItem(g_hWndList, IDC_CHECK_DEBUGGER);
	assert(hWndDebug);
	::SendMessage(hWndDebug, BM_SETCHECK, BST_CHECKED, 0);

	SendMsg(WM_IMPFIX_MODE, 1, 0);
}

//关键脱壳函数
extern "C" void WINAPI StartUnpack(PROCESS_INFORMATION pi, DWORD dwBaseAddress, DWORD dwFixType)
{	
	UpkMgr mgr(pi.dwProcessId, pi.dwThreadId, dwBaseAddress);

	//发消息表示开始脱壳
	TellUnpacker(g_szStartUnpack);

	uint16_t szIatCode[] = {0x50, 0x83, 0xC7};
	DWORD dwNewEip = mgr.findMemory(mgr.getEP(), szIatCode, ARRAY_LEN(szIatCode));
	if (0 == dwNewEip)
	{ 
		TellUnpacker(g_szError);
		return;
	}
	mgr.go(dwNewEip);
	DWORD dwIAT = mgr.getEbx();

	uint16_t szMagicCode[] = {0x61, 0xE9};
	int iAdd = 1;
	DWORD dwCoolEip = mgr.findMemory(dwNewEip, szMagicCode, ARRAY_LEN(szMagicCode), 0x1000);
	if (0 == dwCoolEip)
	{	
		uint16_t szMagicCode[] = {0x6A, 0x00};
		dwCoolEip = mgr.findMemory(dwNewEip, szMagicCode, ARRAY_LEN(szMagicCode), 0x100);
		if (0 == dwCoolEip)
		{
			uint16_t szMagicCode[] = {0x60, 0xE9};
			dwCoolEip = mgr.findMemory(dwNewEip, szMagicCode, ARRAY_LEN(szMagicCode), 0x100);
			if (0 == dwCoolEip)
			{
				TellUnpacker(g_szError);
				return;
			}
		}
		else
			iAdd = 9;
	}
	mgr.go(dwCoolEip);
	DWORD dwOep = mgr.readAJump(dwCoolEip + iAdd);

	SendMsg(WM_TELL_OEP, (WPARAM)dwOep, (LPARAM)dwIAT);
	DumeNow(0, 0);

	TellUnpacker(g_szOK);
}