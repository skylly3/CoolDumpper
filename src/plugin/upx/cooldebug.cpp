// cooldebug.cpp : Defines the initialization routines for the DLL.
//
#include "stdafx.h"
#include "cooldebug.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//�ؼ��ѿǺ���
extern "C" void WINAPI StartUnpack(PROCESS_INFORMATION pi, DWORD dwBaseAddress, DWORD dwEntryPoint)
{	
	DWORD dwPid = pi.dwProcessId;
	DWORD dwTid = pi.dwThreadId;
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, dwTid);
	assert(hProcess);
	assert(hThread);
	//����Ϣ��ʾ��ʼ�ѿ�
	TellUnpacker(g_szStartUnpack);
	UCHAR szIatCode[] = {0x50, 0x83, 0xC7};
	DWORD dwNewEip =  FindMemory(hProcess, dwEntryPoint, szIatCode, sizeof(szIatCode));
	if (0 == dwNewEip)
	{ 
		TellUnpacker(g_szError);
		return Terminate(hProcess, hThread);
	}
	CONTEXT context;
	GO(hProcess, hThread, dwNewEip, context);
	DWORD dwIAT = context.Ebx;

	UCHAR szMagicCode[] = {0x61, 0xE9};
	int iAdd = 1;
	DWORD dwCoolEip = FindMemory(hProcess, dwNewEip, szMagicCode, sizeof(szMagicCode), 0x1000);
	if (0 == dwCoolEip)
	{	
		UCHAR szMagicCode[] = {0x6A, 0x00};
		dwCoolEip = FindMemory(hProcess, dwNewEip, szMagicCode, sizeof(szMagicCode), 0x100);
		if (0 == dwCoolEip)
		{
			UCHAR szMagicCode[] = {0x60, 0xE9};
			dwCoolEip = FindMemory(hProcess, dwNewEip, szMagicCode, sizeof(szMagicCode), 0x100);
			if (0 == dwCoolEip)
			{
				TellUnpacker(g_szError);
				return  Terminate(hProcess, hThread);
			}
		}
		else
			iAdd = 9;
	}
	GO(hProcess, hThread, dwCoolEip, context);
	DWORD dwOep = ReadAJump(hProcess, dwCoolEip + iAdd);
	DumeNow(dwOep, dwIAT);

	TellUnpacker(g_szOK);
	return  Terminate(hProcess, hThread);
}