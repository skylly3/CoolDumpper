#include "../debugger.h"


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
	UpkMgr(DWORD dwPid, DWORD dwTid, DWORD dwBaseAddress)
	{
		m_hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		m_hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, dwTid);

		m_context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		BOOL bOk = ::GetThreadContext(m_hThread, &m_context);
		//assert(bOk);
		if (!bOk)
		{
			tellUnpacker("GetThreadContext fail");
		}
		m_dwBaseAddress = dwBaseAddress;
		m_dwEntryPoint = GetEntryPoint(m_hProcess, m_dwBaseAddress);

		char msg[100];
		sprintf(msg, "eip:%8x entry:%8x", m_context.Eip, m_dwEntryPoint);
		tellUnpacker(msg);

	}
	virtual ~UpkMgr()
	{
		CloseHandle(m_hProcess);
		CloseHandle(m_hThread);
		//通知主程序
		terminate();
	}
public:
	CONTEXT getContext()
	{
		return m_context;;
	}
	DWORD getEP()
	{
		return m_dwEntryPoint;
	}
	DWORD getEip()
	{
		return m_context.Eip;
	}
	DWORD getEsi()
	{
		return m_context.Esi;
	}
	DWORD getEdi()
	{
		return m_context.Edi;
	}
	DWORD getEax()
	{
		return m_context.Eax;
	}
	DWORD getEbx()
	{
		return m_context.Ebx;
	}
	DWORD getEcx()
	{
		return m_context.Ecx;
	}
	DWORD getEdx()
	{
		return m_context.Edx;
	}
	//添加一个断点
	bool addBp(DWORD dwAddr, BP_TYPE type, char* szName)
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
			switch (type)
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
	bool clearBp(DWORD dwAddr, BP_TYPE type)
	{
		std::map<DWORD, tagBP>::iterator iter = m_mapBps.find(dwAddr);
		if (iter != m_mapBps.end())
		{//原来存在
			switch (type)
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
				m_context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

				if (GetThreadContext(m_hThread, &m_context))
				{
					//4. 修正EIP
					m_context.Eip--;
					SetThreadContext(m_hThread, &m_context);
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
		m_context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		BOOL bOk = ::GetThreadContext(m_hThread, &m_context);
		assert(bOk);
		if (!bOk)
			return -1;
		std::map<DWORD, tagBP>::iterator iter = m_mapBps.begin();
		std::map<DWORD, tagBP>::iterator iterEnd = m_mapBps.end();
		for (; iter != iterEnd; iter++)
		{
			switch (iter->second.type)
			{
			case BT_HARD:
			{//硬件断点
			    //硬件断点触发时，dr6必定设置了
				if ((m_context.Dr6 & 0xF) == 0)
					break;
				if (m_context.Eip == iter->second.addr)
				{
					dwAddr = iter->second.addr;
					name = iter->second.name;
					return 1;
				}
				break;
			}
			case BT_SOFT:
			{//EBFE软件断点
				if (m_context.Eip == iter->second.addr)
				{
					dwAddr = iter->second.addr;
					name = iter->second.name;
					return 1;
				}
				break;
			}
			case BT_CC:
			{//CC断点
				if (m_context.Eip == (iter->second.addr + 1))   //CC断点有些特殊，当前EIP比设置的CC位置多一个字节
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
	void terminate()
	{
		::Terminate(m_hProcess, m_hThread);
	}
	//返回用户代码--内部方法
	bool rtu()
	{
		return RTU(m_context);
	}
	//到指定地址--内部方法
	bool go(DWORD dwAddress)
	{
		return GO(m_hProcess, m_hThread, dwAddress, m_context);
	}
	//内存查找
	DWORD findMemory(DWORD dwStartAddress, const UCHAR* pTargetStr, long lStrSize, long lSerchSize = 0x1000)
	{
		return ::FindMemory(m_hProcess, dwStartAddress, pTargetStr, lStrSize, lSerchSize);
	}
	//内存替换
	void replaceMemory(DWORD dwStartAddress, const UCHAR* pTargetStr, const UCHAR* pReplStr, long lStrSize, long lReplSize = 0)
	{
		return ::ReplaceMemory(m_hProcess, dwStartAddress, pTargetStr, pReplStr, lStrSize, lReplSize);
	}
	//写内存
	bool writeMemory(DWORD dwAddress, LPVOID lpBuffer, SIZE_T nSize)
	{
		DWORD dwBytes = 0;
		return ::WriteMemory(m_hProcess, dwAddress, lpBuffer, nSize, &dwBytes);
	}
	//读取内存
	bool readMemory(DWORD dwAddress, LPVOID lpBuffer, SIZE_T nSize)
	{
		DWORD dwBytes = 0;
		return ::ReadMemory(m_hProcess, dwAddress, lpBuffer, nSize, &dwBytes);
	}
	//返回e9 型jump的地址--内部方法
	DWORD readAJump(DWORD dwAddress)
	{
		return ::ReadAJump(m_hProcess, dwAddress);
	}
protected:
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

	//到指定地址--内部方法
	bool GO(HANDLE hProcess, HANDLE hThread, DWORD dwAddress, CONTEXT& context)
	{
		if (!addBp(dwAddress, BT_SOFT, nullptr))
			return false;
		bool bRet = false;
		int iCount = 10;
		while (iCount--)
		{
			resume();
			::Sleep(500);
			DWORD dwAddr = 0;
			std::string strName = "";
			int iRet = isAtBps(dwAddr, strName);
			if (-1 == iRet)
				break;  //出错
			if (1 == iRet)
			{//成功
				bRet = true;
				break;
			}
		}
		clearBp(dwAddress, BT_SOFT);
		return bRet;
	}
	bool setSoftBP(DWORD dwAddress, unsigned char* szBackCode)
	{
		UCHAR szHalt[] = { 0xEB, 0xFE };
		DWORD dwRead;
		ReadMemory(m_hProcess, dwAddress, szBackCode, 2, &dwRead);
		return WriteMemory(m_hProcess, dwAddress, szHalt, 2, &dwRead);
	}
	//清断点--内部方法
	bool clrSoftBP(DWORD dwAddress, unsigned char* szBackCode)
	{
		return WriteMemory(m_hProcess, dwAddress, szBackCode, 2, NULL);
	}

	//设置CC断点
	bool setSoftCC(DWORD dwAddress, unsigned char& szOriCode)
	{
		UCHAR int3 = 0xCC;

		//1. 备份
		ReadProcessMemory(m_hProcess, (LPVOID)dwAddress, &szOriCode, 1, NULL);
		//2. 修改
		return WriteMemory(m_hProcess, dwAddress, &int3, 1, NULL);
	}
	//清除CC断点
	bool clrSoftCC(DWORD dwAddress, unsigned char& szOriCode)
	{
		//2. 修改
		return WriteMemory(m_hProcess, dwAddress, &szOriCode, 1, NULL);
	}

protected:
	//原则上一个地址不能同时设置软断点和硬断点, 减少处理的复杂度, 地址值即可作为key
	std::map<DWORD, tagBP> m_mapBps;
	HANDLE m_hProcess;    //进程句柄
	HANDLE m_hThread;     //线程句柄
	CONTEXT m_context;
	DWORD m_dwBaseAddress; //baseaddr
	DWORD m_dwEntryPoint;  //EP
};

