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
extern "C" void WINAPI StartUnpack(PROCESS_INFORMATION pi, DWORD dwBaseAddress, DWORD dwFixType)
{	
	//发消息表示开始脱壳
	TellUnpacker(g_szStartUnpack);
	
	UpkMgr mgr(pi.dwProcessId, pi.dwThreadId, dwBaseAddress);

	DWORD dwFree = GetAddress("kernel32.dll", "VirtualFree");
	mgr.go(dwFree);
	mgr.rtu();
	mgr.go(dwFree);
	mgr.rtu();
	
	UCHAR patternJmp[] = {0x8B, 0x46, 0x0c};  //机器码：mov eax,[esi+0xC]
	DWORD dwNewEip = mgr.findMemory(mgr.getEip(), patternJmp, sizeof(patternJmp), 0x500);
	if (0 == dwNewEip)
	{
		TellUnpacker(g_szError);
		return;
	}
	mgr.go(dwNewEip);
	DWORD dwIdtStart = mgr.getEsi();
	
	
	UCHAR patternJmp2[] = {0x89, 0x06};  //机器码： mov [esi],eax
	dwNewEip = mgr.findMemory(mgr.getEip(), patternJmp2, sizeof(patternJmp2), 0x500);
	if (0 == dwNewEip)
	{
		TellUnpacker(g_szError);
		return;
	}
	UCHAR nopJmp2[] = {0x90, 0x90, 0x90, 0x90,0x90, 0x90,0x90, 0x90}; 
	mgr.writeMemory(dwNewEip, nopJmp2, sizeof(nopJmp2));
	 
	
	UCHAR patternJmp3[] = {0xC7, 0x03, 0x00, 0x00, 0x00, 0x00};  //机器码： mov [ebx],0
	dwNewEip = mgr.findMemory(mgr.getEip(), patternJmp3, sizeof(patternJmp3), 0x500);
	if (0 != dwNewEip)
	{
		UCHAR nopJmp3[] = { 0x90, 0x90, 0x90, 0x90,0x90, 0x90 };
		mgr.writeMemory(dwNewEip, nopJmp3, sizeof(nopJmp3));
	}

	UCHAR patternJmp4[] = {0xff, 0x07};  //机器码： INC DWORD PTR DS:[EDI]  //call [edi]
	dwNewEip = mgr.findMemory(mgr.getEip(), patternJmp4, sizeof(patternJmp4), 0x500);
	if (0 != dwNewEip)
	{
		if (dwFixType == 2)
		{
			UCHAR nopJmp4[] = {0x90, 0x90}; 
			mgr.writeMemory(dwNewEip, nopJmp4, sizeof(nopJmp4));
		}
		mgr.go(dwNewEip);
		DWORD dwEdi = mgr.getEdi();
	}
	UCHAR patternJmp5[] = { 0x8b, 0x95, -1, -1, -1, -1, 0xe9 };  //机器码:MOV EDX,DWORD PTR SS:[EBP+488];jmp const
	dwNewEip = mgr.findMemory(mgr.getEip(), patternJmp5, sizeof(patternJmp5), 0x500);
	if (0 == dwNewEip)
	{
		TellUnpacker(g_szError);
		return;
	}
	mgr.go(dwNewEip + 11);  // // EIP执行至特征偏移+11位置
	DWORD dwIdtSize = mgr.getEsi() - dwIdtStart + 20;   //IDT size
	DWORD dwImgBase = mgr.getEdx();
	dwIdtStart -= dwImgBase;

	//下面跳OEP
	UCHAR patternJmp6[] = { 0x61, 0x75, 0x08 };  //机器码:POPAD;JNE SHORT 00A17420
	dwNewEip = mgr.findMemory(mgr.getEip(), patternJmp6, sizeof(patternJmp6), 0x500);
	if (0 == dwNewEip)
	{
		TellUnpacker(g_szError);
		return;
	}
	mgr.go(dwNewEip);
	DWORD dwOep = mgr.getEax();


	/*UCHAR szIatCode[] = { 0x8B, 0x18, 0x8B, 0x7E, 0x10, 0x03, 0xFA };
	dwNewEip = mgr.findMemory(mgr.getEP(), szIatCode, sizeof(szIatCode));
	if (0 == dwNewEip)
	{
		TellUnpacker(g_szError);
		return;
	}
	mgr.go(dwNewEip+7);
	DWORD dwIatVA = mgr.getContext().Edi;

	TCHAR msg[100];
	sprintf(msg, "eip:%8x esi:%8x", mgr.getContext().Eip, mgr.getContext().Esi- dwBaseAddress);
	TellUnpacker(msg);*/
	
	//SendMsg(WM_TELL_OEP, (WPARAM)dwBaseAddress + 0x11d2, (LPARAM)dwIatVA);
	
	//DumeNow(0xf0b4, 0xc4);

	//TellUnpacker(g_szOK);
	//return  Terminate(hProcess, hThread);
	//todo: 找出idt地址和范围,避免idt被覆盖


 	SendMsg(WM_TELL_OEP, (WPARAM)dwOep, (LPARAM)0);
	
	DumeNow(dwIdtStart, dwIdtSize);

	TellUnpacker(g_szOK);
}