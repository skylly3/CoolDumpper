#include <Windows.h>
#include <tchar.h>
#include <map>
const DWORD WM_PLUGINMSG_START = WM_USER + 100;						//消息开始
const DWORD WM_SENDSTRING = WM_USER + 101;							//发送字符消息
const DWORD WM_TERMINATE = WM_USER + 102;							//结束脱壳进程
const DWORD WM_TELL_OEP = WM_USER + 103;							//告知OEP
const DWORD WM_DEL_SECTION = WM_USER + 107;                         //移除区段
const DWORD WM_IMPFIX_MODE = WM_USER + 108;                         //插件修复模式选择
const DWORD WM_REBUILD_RES = WM_USER + 111;                         //重建资源

const DWORD WM_DUMPNOW = WM_USER + 105;         					//请求DUMP




const DWORD WM_PLUGINMSG_END = WM_USER + 300;						//消息结束

//#define IDC_CHECK_LOG                   1036
#define IDC_CHECK_DEBUGGER              1043
#include <assert.h>


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
bool WriteMemory(HANDLE hProcess, LPVOID lpAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpByteRead)
{
	bool bRet = false;
	DWORD OldProtect;
	BOOL bOk;
	bOk = VirtualProtectEx(hProcess, (LPVOID)lpAddress, nSize, PAGE_READWRITE, &OldProtect);
	assert(bOk);
	bRet = ::WriteProcessMemory(hProcess, lpAddress, lpBuffer, nSize, lpByteRead) == TRUE;
	assert(bRet);
	bOk = VirtualProtectEx(hProcess, (LPVOID)lpAddress, nSize, OldProtect, &OldProtect);
	assert(bOk);
	return bRet;
}

//内存查找
DWORD FindMemory(HANDLE hProcess, DWORD dwStartAddress, const UCHAR* pTargetStr, long lStrSize, long lSerchSize = 0x1000)
{
	DWORD dwResult = 0;
	UCHAR tempBuff[0x1000]; 
	DWORD dwBytes;
	if (!hProcess) 
		return dwResult;
	ReadMemory(hProcess, dwStartAddress, tempBuff, lSerchSize, &dwBytes);
	for (long lOffset = 0; lOffset < lSerchSize; lOffset++)
		if (0 == ::memcmp(tempBuff + lOffset, pTargetStr, lStrSize))
		{
			dwResult = dwStartAddress + lOffset;
			return dwResult;
		}
		return dwResult;
} 

//内存替换
void ReplaceMemory(HANDLE hProcess, DWORD dwStartAddress, const UCHAR* pTargetStr, const UCHAR* pReplStr, long lStrSize, long lReplSize = 0)
{
	if (lReplSize == 0)
		lReplSize = lStrSize;
	DWORD dwBytes;
	DWORD dwResult = FindMemory(hProcess, dwStartAddress, pTargetStr, lStrSize);
	if (dwResult != 0)
	{
		WriteMemory(hProcess, (LPVOID)dwResult, (LPVOID)pReplStr, lReplSize, &dwBytes);
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

//脱壳辅助类
class UpkMgr
{
public:
	//断点类型
	enum BP_TYPE
	{
		BT_HARD,   //硬件断点 寄存器断点
		BT_SOFT,   //软件断点 EBFE
		BT_CC,     //int3断点
		BT_MEM,    //内存断点
		BT_PAGE,   //页断点
	};

	//断点结构
	struct tagBP
	{
		BP_TYPE type;			//类型
		std::string name;	    //名称
		DWORD addr;				//地址
		UCHAR szBackCode[10];	//代码备份[软件EBFE断点时有用]
		UCHAR szOriCode;	    //代码备份[软件CC断点时有用]
		int iRegIndex;          //调试寄存器序号(硬件断点时有用 0=dr0 1=dr1 2=dr2 3=dr3)
	};
public:
	UpkMgr(DWORD dwPid, DWORD dwTid) 
	{
		m_hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		m_hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, dwTid);
	}
	virtual ~UpkMgr()
	{
		CloseHandle(m_hProcess);
		CloseHandle(m_hThread);
	}
public:
	//添加一个断点
	bool AddBp(DWORD dwAddr, BP_TYPE type, char* szName)
	{
		if (m_mapBps.find(dwAddr) == m_mapBps.end())
		{//原来不存在
			
			tagBP tag;
			tag.addr = dwAddr;
			if (szName)
			{
				tag.name = szName;
			}
			tag.type = type;
			switch(type)
			{
			case BT_HARD:
				{//硬件断点
					if (!SetExecuteBP(m_hThread, tag.iRegIndex, dwAddr))
						return false;
					break;
				}
			case BT_SOFT:
				{//软件断点
					if (!setSoftBP(dwAddr, tag.szBackCode))
						return false;
					break;
				}
			case BT_CC:
				{//CC断点
					if (!setSoftCC(dwAddr, tag.szOriCode))
						return false;
					break;
				}
			default: //暂不支持
				return false;
				break;
			}
			m_mapBps.insert(std::make_pair(dwAddr, tag));
			return true;
		}
		return false;
	}
	//删除一个断点
	bool ClearBp(DWORD dwAddr, BP_TYPE type)
	{
		std::map<DWORD, tagBP>::iterator iter = m_mapBps.find(dwAddr);
		if (iter != m_mapBps.end())
		{//原来存在
			switch(type)
			{
			case BT_HARD:
				{//硬件断点
					if (!ClearExecuteBP(m_hThread, iter->second.iRegIndex, dwAddr))
						return false;		 
					break;
				}
			case BT_SOFT:
				{//软件断点
					if (!clrSoftBP(dwAddr, iter->second.szBackCode))
						return false;
					break;
				}
			case BT_CC:
				{//CC断点
					CONTEXT context;
					context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

					if (GetThreadContext(m_hThread, &context)) 
					{
						//4. 修正EIP
						context.Eip--;
						SetThreadContext(m_hThread, &context);
					}

					if (!clrSoftCC(dwAddr, iter->second.szOriCode))
						return false;
					break;
				}
			default: //暂不支持
				return false;
				break;
			}		

			m_mapBps.erase(iter);
			return true;
		}
		return false;
	}
	DWORD getEip()
	{
		CONTEXT context;
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		BOOL bOk = ::GetThreadContext(m_hThread, &context);
		assert(bOk);
		if (!bOk)
			return 0;
		return context.Eip;
	}
	////是否到达断点 这个判断不准确,比如cc断点,eip就和断点位置差一字节
	//bool isAtBp(DWORD dwAddr, bool bSuspend = true)
	//{
	//	if (bSuspend)
	//		::SuspendThread(m_hThread);
	//	CONTEXT context;
	//	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	//	BOOL bOk = ::GetThreadContext(m_hThread, &context);
	//	assert(bOk);
	//	if (!bOk)
	//		return false;
	//	return context.Eip == dwAddr;
	//}

	//是否到达断点 1=到达 0=未到达 -1=失败
	int isAtBps(DWORD& dwAddr, std::string& name, bool bSuspend = true)
	{
		if (bSuspend)
			::SuspendThread(m_hThread);
		CONTEXT context;
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		BOOL bOk = ::GetThreadContext(m_hThread, &context);
		assert(bOk);
		if (!bOk)
			return -1;
		std::map<DWORD, tagBP>::iterator iter = m_mapBps.begin();
		std::map<DWORD, tagBP>::iterator iterEnd = m_mapBps.end();
		for (;iter != iterEnd; iter++)
		{
			switch(iter->second.type)
			{
			case BT_HARD:
				{//硬件断点
					//硬件断点触发时，dr6必定设置了
					if ((context.Dr6 & 0xF) == 0)
						break;
					if (context.Eip == iter->second.addr)
					{
						dwAddr = iter->second.addr;
						name = iter->second.name;
						return 1;
					}
					break;
				}
			case BT_SOFT:
				{//EBFE软件断点
					if (context.Eip == iter->second.addr)
					{
						dwAddr = iter->second.addr;
						name = iter->second.name;
						return 1;
					}
					break;
				}
			case BT_CC:
				{//CC断点
					if (context.Eip == (iter->second.addr+1))   //CC断点有些特殊，当前EIP比设置的CC位置多一个字节
					{
						dwAddr = iter->second.addr;
						name = iter->second.name;
						return 1;
					}
					break;
				}
			default:
				//暂不支持
				break;
			}//switch断点类型
		}//for


		//std::map<DWORD, tagBP>::iterator iter = m_mapBps.find(context.Eip);
		//if (iter != m_mapBps.end())
		//{//当前IP位于断点
		//	if (iter->second.type == BT_HARD)
		//	{//硬件断点触发时，dr6必定设置了
		//		if ((context.Dr6 & 0xF) == 0)
		//			return 0;
		//	}
		//	dwAddr = context.Eip;
		//	name = iter->second.name;
		//	return 1;
		//}
		return 0;
	}

	void resume()
	{
		// 继续新进程的执行
		ResumeThread(m_hThread);
	}
	//到指定地址--内部方法
	bool GO(HANDLE hProcess, HANDLE hThread, DWORD dwAddress, CONTEXT& context)
	{
		unsigned char szBackCode[10];
		setSoftBP(dwAddress, szBackCode);
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		BOOL bOk = FALSE;
		bOk = ::GetThreadContext(hThread, &context);
		assert(bOk);
		DWORD dwCurEip = context.Eip;
		int iCount = 10;
		while ((dwCurEip != dwAddress) && (iCount--))
		{
			resume();
			::Sleep(1000);
			::SuspendThread(m_hThread);
			dwCurEip = getEip();
		}
		clrSoftBP(dwAddress, szBackCode);
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		bOk = ::GetThreadContext(hThread, &context);
		assert(bOk);
		return true;
	}

	//返回用户代码--内部方法
	bool RTU(CONTEXT& context)
	{
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		BOOL bOk = ::GetThreadContext(m_hThread, &context);
		assert(bOk);
		DWORD dwEspCODE;
		DWORD dwRead;
		ReadMemory(m_hProcess, context.Esp, &dwEspCODE, 4, &dwRead);
		GO(m_hProcess, m_hThread, dwEspCODE, context);
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		bOk = ::GetThreadContext(m_hThread, &context);
		assert(bOk);
		return true;
	}

protected:
	bool setSoftBP(DWORD dwAddress, unsigned char* szBackCode)
	{
		UCHAR szHalt[] = {0xEB, 0xFE};
		DWORD dwRead;
		ReadMemory(m_hProcess, dwAddress, szBackCode, 2, &dwRead);
		return WriteMemory(m_hProcess, (LPVOID)dwAddress, szHalt, 2, &dwRead);
	}
	//清断点--内部方法
	bool clrSoftBP(DWORD dwAddress, unsigned char* szBackCode)
	{
		return WriteMemory(m_hProcess, (LPVOID)dwAddress, szBackCode, 2, NULL);
	}

	//设置CC断点
	bool setSoftCC(DWORD dwAddress, unsigned char& szOriCode)
	{
		UCHAR int3 = 0xCC;

		//1. 备份
		ReadProcessMemory(m_hProcess, (LPVOID)dwAddress, &szOriCode, 1, NULL);
		//2. 修改
		return WriteMemory(m_hProcess, (LPVOID)dwAddress, &int3, 1, NULL);
	}
	//清除CC断点
	bool clrSoftCC(DWORD dwAddress, unsigned char& szOriCode)
	{
		//2. 修改
		return WriteMemory(m_hProcess, (LPVOID)dwAddress, &szOriCode, 1, NULL);
	}

protected:
	//原则上一个地址不能同时设置软断点和硬断点, 减少处理的复杂度, 地址值即可作为key
	std::map<DWORD, tagBP> m_mapBps;
	HANDLE m_hProcess;    //进程句柄
	HANDLE m_hThread;     //线程句柄
};

