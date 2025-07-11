// cooldebug.cpp : Defines the initialization routines for the DLL.
//
#include "stdafx.h"
//#include <afxdllx.h>
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

	SendMsg(WM_IMPFIX_MODE, 2, 0);
}

//关键函数
extern "C" void WINAPI StartUnpack(PROCESS_INFORMATION pi, DWORD dwBaseAddress, DWORD dwEntryPoint)
{	
	DWORD dwPid = pi.dwProcessId;
	DWORD dwTid = pi.dwThreadId;
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, dwTid);
	assert(hProcess);
	assert(hThread);
	//发消息表示开始脱壳
	TellUnpacker(g_szStartUnpack);
	
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	BOOL bOk = ::GetThreadContext(hThread, &context);
	//assert(bOk);
	if (!bOk)
	{
		TellUnpacker("GetThreadContext fail");
	}

	TCHAR msg[100];
	sprintf(msg, "eip:%8x entry:%8x", context.Eip, dwEntryPoint);
	TellUnpacker(msg);

	UCHAR szIatCode[] = { 0x8B, 0x18, 0x8B, 0x7E, 0x10, 0x03, 0xFA };
	DWORD dwNewEip = FindMemory(hProcess, dwEntryPoint, szIatCode, sizeof(szIatCode));
	if (0 == dwNewEip)
	{
		TellUnpacker(g_szError);
		return Terminate(hProcess, hThread);
	}
	GO(hProcess, hThread, dwNewEip+7, context);
	DWORD dwIatVA = context.Edi;
	sprintf(msg, "eip:%8x esi:%8x", context.Eip, context.Esi- dwBaseAddress);
	TellUnpacker(msg);
	
	SendMsg(WM_TELL_OEP, (WPARAM)dwBaseAddress + 0x11d2, (LPARAM)dwIatVA);
	
	DumeNow(0xf0b4, 0xc4);

	TellUnpacker(g_szOK);
	return  Terminate(hProcess, hThread);


	UCHAR szMagicCode[] = {0x61, 0x75, 0x08, 0xB8, 0x01, 0x00, 0x00, 0x00};
	DWORD dwCoolEip = FindMemory(hProcess, dwEntryPoint-1, szMagicCode, sizeof(szMagicCode), 0x1000);
	if (0 == dwCoolEip)
	{	

		TellUnpacker(g_szError);
		return  Terminate(hProcess, hThread);
	}
	GO(hProcess, hThread, dwCoolEip+1, context);

	DWORD dwOep = 0;
	DWORD dwRead = 0;
	ReadMemory(hProcess, dwCoolEip + 12, &dwOep, 4, &dwRead);
 
	
	DumeNow(0xf0b4, 0xc4);

	TellUnpacker(g_szOK);
	return  Terminate(hProcess, hThread);
}