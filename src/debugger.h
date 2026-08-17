const DWORD WM_PLUGINMSG_START = WM_USER + 100;						//消息开始
const DWORD WM_SENDSTRING = WM_USER + 101;							//发送字符消息
const DWORD WM_TERMINATE = WM_USER + 102;							//结束脱壳进程
const DWORD WM_TELL_OEP = WM_USER + 103;							//告知OEP
const DWORD WM_DEL_SECTION = WM_USER + 107;                         //移除区段
const DWORD WM_IMPFIX_MODE = WM_USER + 108;                         //插件修复模式选择
const DWORD WM_REBUILD_RES = WM_USER + 111;                         //重建资源

const DWORD WM_DUMPNOW = WM_USER + 105;         					//请求DUMP

const DWORD WM_PLUGINMSG_END = WM_USER + 300;						//消息结束

//#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))
template <typename T, size_t N>
constexpr size_t ARRAY_LEN(T(&)[N]) noexcept {
	return N;
}
																	//#define IDC_CHECK_LOG                   1036
#define IDC_CHECK_DEBUGGER              1066
#include <assert.h>
#include <Windows.h>
#include <tchar.h>
#include <map>

//#include <psapi.h>  //MODULEINFO
//#pragma comment(lib, "psapi.lib")
//// 获取进程的主模块（可执行文件）信息
//bool GetMainModuleInfo(HANDLE hProcess, MODULEINFO& moduleInfo) {
//	HMODULE hModules[1024];
//	DWORD cbNeeded;
//
//	// 枚举进程模块
//	if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded))
//	{
//		char msg[100];
//		DWORD dwErr = GetLastError();
//		sprintf(msg, "EnumProcessModules failed. Error: %d", dwErr);
//		if (dwErr == 299)
//		{//
//			Sleep(500);  //等待100ms  再试一次
//			if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded))
//			{
//				dwErr = GetLastError();
//				sprintf(msg, "EnumProcessModules failed. Error: %d", dwErr);
//				return false;
//			}
//		}
//		else
//			return false;
//	}
//
//	// 获取主模块信息（第一个模块通常是可执行文件）
//	if (!GetModuleInformation(hProcess, hModules[0], &moduleInfo, sizeof(MODULEINFO))) {
//		//std::cerr << "GetModuleInformation failed. Error: " << GetLastError() << std::endl;
//		return false;
//	}
//
//	return true;
//}

// 从模块基地址获取入口点
DWORD GetEntryPoint(HANDLE hProcess, const DWORD dwBaseAddr) {
	// 读取模块的DOS头
	IMAGE_DOS_HEADER dosHeader;
	if (!ReadProcessMemory(hProcess, (LPCVOID)dwBaseAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr)) {
		//std::cerr << "ReadProcessMemory failed (DOS header). Error: " << GetLastError() << std::endl;
		return 0;
	}

	// 读取模块的NT头
	IMAGE_NT_HEADERS ntHeaders;
	LPVOID ntHeaderAddr = (LPVOID)(dwBaseAddr + dosHeader.e_lfanew);
	if (!ReadProcessMemory(hProcess, ntHeaderAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS), nullptr)) {
		//	std::cerr << "ReadProcessMemory failed (NT headers). Error: " << GetLastError() << std::endl;
		return 0;
	}

	// 入口点相对基地址的偏移量加上基地址就是实际入口点地址
	return (DWORD)(dwBaseAddr + ntHeaders.OptionalHeader.AddressOfEntryPoint);
}
//获得函数地址
DWORD GetAddress(LPCTSTR lpModName, LPCSTR lpProcName)
{
	HMODULE hMod = ::GetModuleHandle(lpModName);
	if (NULL != hMod)
	{
		return (DWORD)::GetProcAddress(hMod, lpProcName);
	}
	return NULL;
}

//读取内存
bool ReadMemory(HANDLE hProcess, DWORD dwAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpByteRead)
{
	DWORD OldProtect;
	BOOL bOk;

	bOk = ::ReadProcessMemory(hProcess, (LPCVOID)dwAddress, lpBuffer, nSize, lpByteRead);
	if (!bOk)
	{//失败了，争取一下权限
		DWORD dwErr = GetLastError();
		bOk = VirtualProtectEx(hProcess, (LPVOID)dwAddress, nSize, PAGE_READWRITE, &OldProtect);
		assert(bOk);

		if (bOk)
		{
			bOk = ::ReadProcessMemory(hProcess, (LPCVOID)dwAddress, lpBuffer, nSize, lpByteRead);
			VirtualProtectEx(hProcess, (LPVOID)dwAddress, nSize, OldProtect, &OldProtect);
			if (!bOk)
			{//还原权限
				return false;
			}
		}
		if (!bOk)
		{
			dwErr = GetLastError();
			return false;
		}
	}
	assert(bOk);

	return true;
}

//写内存
bool WriteMemory(HANDLE hProcess, DWORD dwAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpByteWrite)
{
	bool bRet = false;
	DWORD OldProtect;
	BOOL bOk;
	bOk = VirtualProtectEx(hProcess, (LPVOID)dwAddress, nSize, PAGE_READWRITE, &OldProtect);
	assert(bOk);
	bRet = ::WriteProcessMemory(hProcess, (LPVOID)dwAddress, lpBuffer, nSize, lpByteWrite) == TRUE;
	assert(bRet);
	bOk = VirtualProtectEx(hProcess, (LPVOID)dwAddress, nSize, OldProtect, &OldProtect);
	assert(bOk);
	return bRet;
}

//内存查找（支持通配符，0xFF匹配任意字节）
DWORD FindMemory(HANDLE hProcess, DWORD dwStartAddress, const uint16_t* pTargetStr, long lStrSize, long lSerchSize = 0x1000)
{
    DWORD dwResult = 0;
    UCHAR tempBuff[0x1000];
    DWORD dwBytes;
    
    if (!hProcess)
        return dwResult;
    
    ReadMemory(hProcess, dwStartAddress, tempBuff, lSerchSize, &dwBytes);
    
    // 遍历搜索区域
    for (long lOffset = 0; lOffset <= lSerchSize - lStrSize; lOffset++)
    {
        bool bMatch = true;
        
        // 逐字节比较，支持通配符
        for (long i = 0; i < lStrSize; i++)
        {
            // 如果模式字节是-1，则跳过比较（匹配任意字节）
            if (pTargetStr[i] == uint16_t(-1))
                continue;
            
            // 否则必须完全匹配
            if (tempBuff[lOffset + i] != (uint8_t)(pTargetStr[i]))
            {
                bMatch = false;
                break;
            }
        }
        
        if (bMatch)
        {
            dwResult = dwStartAddress + lOffset;
            return dwResult;
        }
    }
    
    return dwResult;
}

//内存替换
void ReplaceMemory(HANDLE hProcess, DWORD dwStartAddress, const uint16_t* pTargetStr, const UCHAR* pReplStr, long lStrSize, long lReplSize = 0)
{
	if (lReplSize == 0)
		lReplSize = lStrSize;

	DWORD dwResult = FindMemory(hProcess, dwStartAddress, pTargetStr, lStrSize);
	if (dwResult != 0)
	{
		DWORD dwBytes = 0;
		WriteMemory(hProcess, dwResult, (LPVOID)pReplStr, lReplSize, &dwBytes);
	}
}

//返回e9 型jump的地址--内部方法
DWORD ReadAJump(HANDLE hProcess, DWORD dwAddress)
{
	BOOL bOk = FALSE;
	DWORD dwRead;
	DWORD dwOffset;
	ReadMemory(hProcess, dwAddress + 1, &dwOffset, sizeof(dwOffset), &dwRead);
	return (dwOffset + dwAddress + 5);
}
//
////设置CC断点
//VOID SetInt3BreakPoint(HANDLE hProcess, char& szOriCode, LPVOID addr)
//{
//	CHAR int3 = 0xCC;
//	
//	//1. 备份
//	ReadProcessMemory(hProcess, addr, &szOriCode, 1, NULL);
//	//2. 修改
//	WriteProcessMemory(hProcess, addr, &int3, 1, NULL);
//}

//设置硬件断点
bool SetExecuteBP(HANDLE hThread, int& iRegIndex, DWORD_PTR address) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (GetThreadContext(hThread, &context))
	{
		// 寻找可用的硬件断点寄存器
		for (int i = 0; i < 4; i++)
		{
			if ((context.Dr7 & (1 << (i * 2))) == 0)
			{
				iRegIndex = i;
				break;
			}
		}

		if (iRegIndex != -1)
		{
			// 设置断点寄存器
			// 断点长度(LENx)：00(1字节)、01(2字节)、11(4字节)
			// 断点类型(R/Wx)：00(执行断点)、01(写入断点)、11(访问断点)
			switch (iRegIndex) {
			case 0:
				context.Dr0 = address;
				context.Dr7 &= 0xfff0ffff; // 设置断点类型为执行断点(16位，17位为00)， 断点长度1字节(18,19位为00)
				break;
			case 1:
				context.Dr1 = address;
				context.Dr7 &= 0xff0fffff;
				break;
			case 2:
				context.Dr2 = address;
				context.Dr7 &= 0xf0ffffff;
				break;
			case 3:
				context.Dr3 = address;
				context.Dr7 &= 0x0fffffff;
				break;
			}

			// 设置断点类型
			context.Dr7 |= (1 << (iRegIndex * 2)); // 使能断点


												   // 更新线程上下文
			return SetThreadContext(hThread, &context) == TRUE;
		}//找到了可用的寄存器
	}//取到了context
	return false;
}

//清除硬件断点
bool ClearExecuteBP(HANDLE hThread, const int iRegIndex, DWORD_PTR address) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

	if (GetThreadContext(hThread, &context))
	{
		if (iRegIndex != -1)
		{
			// 设置断点寄存器
			switch (iRegIndex) {
			case 0:
				context.Dr0 = 0;
				context.Dr7 &= 0xfffffffe;      // 不使能断点
				break;
			case 1:
				context.Dr1 = 0;
				context.Dr7 &= 0xfffffffb;      // 不使能断点
				break;
			case 2:
				context.Dr2 = 0;
				context.Dr7 &= 0xffffffef;      // 不使能断点
				break;
			case 3:
				context.Dr3 = 0;
				context.Dr7 &= 0xffffffbf;      // 不使能断点
				break;
			}

			// 更新线程上下文
			return SetThreadContext(hThread, &context) == TRUE;
		}//找到了可用的寄存器
	}//取到了context
	return false;
}

//底层消息是实现
void sendMsg(UINT uMsg, WPARAM wParam, LPARAM lParam, HWND hWnd = g_hWndList)
{
	if (hWnd != NULL)
		::SendMessage(hWnd, uMsg, wParam, lParam);
}
//向脱壳机传递字符串
void tellUnpacker(std::string strMsg)
{
	::ZeroMemory(g_szNewMsg, 256);
	strcat(g_szNewMsg, g_szAboutMe);
	strcat(g_szNewMsg, strMsg.c_str());
	static    char   *pStr = g_szNewMsg;
	sendMsg(WM_SENDSTRING, (WPARAM)pStr, 0);
}

//下断点--内部方法
void BP(HANDLE hProcess, DWORD dwAddress)
{
	UCHAR szHalt[] = { 0xEB, 0xFE };
	DWORD dwRead;
	ReadMemory(hProcess, dwAddress, g_szBackCode, 2, &dwRead);
	WriteMemory(hProcess, dwAddress, szHalt, 2, &dwRead);
}

//清断点--内部方法
void BC(HANDLE hProcess, DWORD dwAddress)
{
	UCHAR szHalt[] = { 0xEB, 0xFE };
	DWORD dwRead;
	WriteMemory(hProcess, dwAddress, g_szBackCode, 2, &dwRead);
	//ASSERT(bOk);
}

//向脱壳机表示继续进程
void Resume(HANDLE hThread)
{
	//继续目标进程
	::ResumeThread(hThread);
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

//底层消息是实现
void SendMsg(UINT uMsg, WPARAM wParam, LPARAM lParam, HWND hWnd = g_hWndList)
{
	if (hWnd != NULL)
		::SendMessage(hWnd, uMsg, wParam, lParam);
}

//向脱壳机表示结束脱壳过程并进行适当清理
void Terminate(HANDLE hProcess, HANDLE hThread)
{
	//::CloseHandle(hProcess);
	//::CloseHandle(hThread);
	SendMsg(WM_TERMINATE, 0, 0);
}

//向脱壳机表示dump
void DumeNow(DWORD dwIdt = 0, DWORD dwIdtSize = 0)
{
	SendMsg(WM_DUMPNOW, (WPARAM)dwIdt, (LPARAM)dwIdtSize);
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

//关于插件--API
extern "C" void WINAPI AboutPlugin()
{
	TellUnpacker(g_szVersion);
}

