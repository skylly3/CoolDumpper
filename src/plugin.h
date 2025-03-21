#include "debugger.h"
#include <string>

//底层消息是实现
void SendMsg(UINT uMsg, WPARAM wParam, LPARAM lParam, HWND hWnd = g_hWndList)
{
	if (hWnd != NULL)
		::SendMessage(hWnd, uMsg, wParam, lParam);
}
//向脱壳机传递字符串
void TellUnpacker(std::string strMsg)
{
	::ZeroMemory(g_szNewMsg, 256);
	strcat(g_szNewMsg, g_szAboutMe);
	strcat(g_szNewMsg, strMsg.c_str());
	static    char   *pStr = g_szNewMsg;
	SendMsg(WM_SENDSTRING, (WPARAM)pStr, 0);
}

//向脱壳机表示结束脱壳过程并进行适当清理
void Terminate(HANDLE hProcess, HANDLE hThread)
{
	::CloseHandle(hProcess);
	::CloseHandle(hThread);
	SendMsg(WM_TERMINATE, 0, 0);
}
//向脱壳机表示继续进程
void Resume(HANDLE hThread)
{
	//继续目标进程
	::ResumeThread(hThread);
}

//向脱壳机表示dump
void DumeNow(DWORD dwOEP = 0, DWORD dwIAT = 0)
{
	SendMsg(WM_DUMPNOW, (WPARAM)dwOEP, (LPARAM)dwIAT);
}

//向脱壳机表示暂停
CONTEXT Halt(HANDLE hThread)
{
	::SuspendThread(hThread);
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	BOOL bOk = ::GetThreadContext(hThread, &context);
	assert(bOk);
	return context;
}

//下断点--内部方法
void BP(HANDLE hProcess, DWORD dwAddress)
{
	UCHAR szHalt[] = {0xEB, 0xFE};
	DWORD dwRead;
    ReadMemory(hProcess, dwAddress, g_szBackCode, 2, &dwRead);
	WriteMemory(hProcess, (LPVOID)dwAddress, szHalt, 2, &dwRead);
}

//清断点--内部方法
void BC(HANDLE hProcess, DWORD dwAddress)
{
	UCHAR szHalt[] = {0xEB, 0xFE};
	DWORD dwRead;
	WriteMemory(hProcess, (LPVOID)dwAddress, g_szBackCode, 2, &dwRead);
	//ASSERT(bOk);
}

//到指定地址--内部方法
bool GO(HANDLE hProcess, HANDLE hThread, DWORD dwAddress, CONTEXT& context)
{
	BP(hProcess, dwAddress);
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	BOOL bOk = FALSE;
	bOk = ::GetThreadContext(hThread, &context);
	assert(bOk);
	DWORD dwCurEip = context.Eip;
	int iCount = 10;
	while ((dwCurEip != dwAddress) && (iCount--))
	{
		Resume(hThread);
		::Sleep(1000);
		context = Halt(hThread);			//暂停进程
		dwCurEip = context.Eip;
	}
	BC(hProcess, dwAddress);
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	bOk = ::GetThreadContext(hThread, &context);
	assert(bOk);
	return true;
}

//返回用户代码--内部方法
bool RTU(HANDLE hProcess, HANDLE hThread, CONTEXT& context)
{
	BOOL bOk = FALSE;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	bOk = ::GetThreadContext(hThread, &context);
	assert(bOk);
	DWORD dwEspCODE;
	DWORD dwRead;
	ReadMemory(hProcess, context.Esp, &dwEspCODE, 4, &dwRead);
	GO(hProcess, hThread, dwEspCODE, context);
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	bOk = ::GetThreadContext(hThread, &context);
	assert(bOk);
	return true;
}

//关于插件--API
extern "C" void WINAPI AboutPlugin()
{	
	TellUnpacker(g_szVersion);
}

//初始化--API
extern "C" void WINAPI InitPlugin(HWND hWnd)
{
	g_hWndList = hWnd;
	TellUnpacker(g_szInitOk);
	HWND hWndDebug = ::GetDlgItem(g_hWndList, IDC_CHECK_DEBUGGER);
	assert(hWndDebug);
	::SendMessage(hWndDebug, BM_SETCHECK, 0, 0);
}
