#include <Windows.h>
#include <tchar.h>
#include <map>
const DWORD WM_PLUGINMSG_START = WM_USER + 100;						//��Ϣ��ʼ
const DWORD WM_SENDSTRING = WM_USER + 101;							//�����ַ���Ϣ
const DWORD WM_TERMINATE = WM_USER + 102;							//�����ѿǽ���
const DWORD WM_TELL_OEP = WM_USER + 103;							//��֪OEP
const DWORD WM_DEL_SECTION = WM_USER + 107;                         //�Ƴ�����
const DWORD WM_IMPFIX_MODE = WM_USER + 108;                         //����޸�ģʽѡ��
const DWORD WM_REBUILD_RES = WM_USER + 111;                         //�ؽ���Դ

const DWORD WM_DUMPNOW = WM_USER + 105;         					//����DUMP




const DWORD WM_PLUGINMSG_END = WM_USER + 300;						//��Ϣ����

//#define IDC_CHECK_LOG                   1036
#define IDC_CHECK_DEBUGGER              1043
#include <assert.h>


//��ú�����ַ
DWORD GetAddress(LPCTSTR lpModName, LPCSTR lpProcName)
{
	HMODULE hMod = ::GetModuleHandle(lpModName);
	if (NULL != hMod)
	{
		return (DWORD)::GetProcAddress(hMod, lpProcName);
	}
	return NULL;
}

//��ȡ�ڴ�
bool ReadMemory(HANDLE hProcess, DWORD dwAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpByteRead)
{
	DWORD OldProtect;
	BOOL bOk;
	
	bOk = ::ReadProcessMemory(hProcess, (LPCVOID)dwAddress, lpBuffer, nSize, lpByteRead);
	if (!bOk)
	{//ʧ���ˣ���ȡһ��Ȩ��
		DWORD dwErr = GetLastError();
		bOk = VirtualProtectEx(hProcess, (LPVOID)dwAddress, nSize, PAGE_READWRITE, &OldProtect);
		assert(bOk);

		if (bOk)
		{
			bOk = ::ReadProcessMemory(hProcess, (LPCVOID)dwAddress, lpBuffer, nSize, lpByteRead);
			VirtualProtectEx(hProcess, (LPVOID)dwAddress, nSize, OldProtect, &OldProtect);
			if (!bOk)
			{//��ԭȨ��
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

//д�ڴ�
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

//�ڴ����
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

//�ڴ��滻
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

//����e9 ��jump�ĵ�ַ--�ڲ�����
DWORD ReadAJump(HANDLE hProcess, DWORD dwAddress)
{
	BOOL bOk = FALSE;
	DWORD dwRead;
	DWORD dwOffset;
	ReadMemory(hProcess, dwAddress + 1, &dwOffset, sizeof(dwOffset), &dwRead);
	return (dwOffset + dwAddress + 5);
}
//
////����CC�ϵ�
//VOID SetInt3BreakPoint(HANDLE hProcess, char& szOriCode, LPVOID addr)
//{
//	CHAR int3 = 0xCC;
//	
//	//1. ����
//	ReadProcessMemory(hProcess, addr, &szOriCode, 1, NULL);
//	//2. �޸�
//	WriteProcessMemory(hProcess, addr, &int3, 1, NULL);
//}

//����Ӳ���ϵ�
bool SetExecuteBP(HANDLE hThread, int& iRegIndex, DWORD_PTR address) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(hThread, &context)) 
	{
        // Ѱ�ҿ��õ�Ӳ���ϵ�Ĵ���
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
            // ���öϵ�Ĵ���
			// �ϵ㳤��(LENx)��00(1�ֽ�)��01(2�ֽ�)��11(4�ֽ�)
			// �ϵ�����(R/Wx)��00(ִ�жϵ�)��01(д��ϵ�)��11(���ʶϵ�)
            switch (iRegIndex) {
                case 0:
                    context.Dr0 = address;
					context.Dr7 &= 0xfff0ffff; // ���öϵ�����Ϊִ�жϵ�(16λ��17λΪ00)�� �ϵ㳤��1�ֽ�(18,19λΪ00)
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

            // ���öϵ�����
            context.Dr7 |= (1 << (iRegIndex * 2)); // ʹ�ܶϵ�
           

            // �����߳�������
            return SetThreadContext(hThread, &context) == TRUE;
        }//�ҵ��˿��õļĴ���
    }//ȡ����context
	return false;
}

//���Ӳ���ϵ�
bool ClearExecuteBP(HANDLE hThread, const int iRegIndex, DWORD_PTR address) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(hThread, &context)) 
	{
        if (iRegIndex != -1) 
		{
            // ���öϵ�Ĵ���
            switch (iRegIndex) {
                case 0:
                    context.Dr0 = 0;
					context.Dr7 &= 0xfffffffe;      // ��ʹ�ܶϵ�
                    break;
                case 1:
                    context.Dr1 = 0;
					context.Dr7 &= 0xfffffffb;      // ��ʹ�ܶϵ�
                    break;
                case 2:
                    context.Dr2 = 0;
					context.Dr7 &= 0xffffffef;      // ��ʹ�ܶϵ�
                    break;
                case 3:
                    context.Dr3 = 0;
					context.Dr7 &= 0xffffffbf;      // ��ʹ�ܶϵ�
                    break;
            }

            // �����߳�������
            return SetThreadContext(hThread, &context) == TRUE;
        }//�ҵ��˿��õļĴ���
    }//ȡ����context
	return false;
}

//�ѿǸ�����
class UpkMgr
{
public:
	//�ϵ�����
	enum BP_TYPE
	{
		BT_HARD,   //Ӳ���ϵ� �Ĵ����ϵ�
		BT_SOFT,   //����ϵ� EBFE
		BT_CC,     //int3�ϵ�
		BT_MEM,    //�ڴ�ϵ�
		BT_PAGE,   //ҳ�ϵ�
	};

	//�ϵ�ṹ
	struct tagBP
	{
		BP_TYPE type;			//����
		std::string name;	    //����
		DWORD addr;				//��ַ
		UCHAR szBackCode[10];	//���뱸��[���EBFE�ϵ�ʱ����]
		UCHAR szOriCode;	    //���뱸��[���CC�ϵ�ʱ����]
		int iRegIndex;          //���ԼĴ������(Ӳ���ϵ�ʱ���� 0=dr0 1=dr1 2=dr2 3=dr3)
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
	//���һ���ϵ�
	bool AddBp(DWORD dwAddr, BP_TYPE type, char* szName)
	{
		if (m_mapBps.find(dwAddr) == m_mapBps.end())
		{//ԭ��������
			
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
				{//Ӳ���ϵ�
					if (!SetExecuteBP(m_hThread, tag.iRegIndex, dwAddr))
						return false;
					break;
				}
			case BT_SOFT:
				{//����ϵ�
					if (!setSoftBP(dwAddr, tag.szBackCode))
						return false;
					break;
				}
			case BT_CC:
				{//CC�ϵ�
					if (!setSoftCC(dwAddr, tag.szOriCode))
						return false;
					break;
				}
			default: //�ݲ�֧��
				return false;
				break;
			}
			m_mapBps.insert(std::make_pair(dwAddr, tag));
			return true;
		}
		return false;
	}
	//ɾ��һ���ϵ�
	bool ClearBp(DWORD dwAddr, BP_TYPE type)
	{
		std::map<DWORD, tagBP>::iterator iter = m_mapBps.find(dwAddr);
		if (iter != m_mapBps.end())
		{//ԭ������
			switch(type)
			{
			case BT_HARD:
				{//Ӳ���ϵ�
					if (!ClearExecuteBP(m_hThread, iter->second.iRegIndex, dwAddr))
						return false;		 
					break;
				}
			case BT_SOFT:
				{//����ϵ�
					if (!clrSoftBP(dwAddr, iter->second.szBackCode))
						return false;
					break;
				}
			case BT_CC:
				{//CC�ϵ�
					CONTEXT context;
					context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

					if (GetThreadContext(m_hThread, &context)) 
					{
						//4. ����EIP
						context.Eip--;
						SetThreadContext(m_hThread, &context);
					}

					if (!clrSoftCC(dwAddr, iter->second.szOriCode))
						return false;
					break;
				}
			default: //�ݲ�֧��
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
	////�Ƿ񵽴�ϵ� ����жϲ�׼ȷ,����cc�ϵ�,eip�ͺͶϵ�λ�ò�һ�ֽ�
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

	//�Ƿ񵽴�ϵ� 1=���� 0=δ���� -1=ʧ��
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
				{//Ӳ���ϵ�
					//Ӳ���ϵ㴥��ʱ��dr6�ض�������
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
				{//EBFE����ϵ�
					if (context.Eip == iter->second.addr)
					{
						dwAddr = iter->second.addr;
						name = iter->second.name;
						return 1;
					}
					break;
				}
			case BT_CC:
				{//CC�ϵ�
					if (context.Eip == (iter->second.addr+1))   //CC�ϵ���Щ���⣬��ǰEIP�����õ�CCλ�ö�һ���ֽ�
					{
						dwAddr = iter->second.addr;
						name = iter->second.name;
						return 1;
					}
					break;
				}
			default:
				//�ݲ�֧��
				break;
			}//switch�ϵ�����
		}//for


		//std::map<DWORD, tagBP>::iterator iter = m_mapBps.find(context.Eip);
		//if (iter != m_mapBps.end())
		//{//��ǰIPλ�ڶϵ�
		//	if (iter->second.type == BT_HARD)
		//	{//Ӳ���ϵ㴥��ʱ��dr6�ض�������
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
		// �����½��̵�ִ��
		ResumeThread(m_hThread);
	}
	//��ָ����ַ--�ڲ�����
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

	//�����û�����--�ڲ�����
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
	//��ϵ�--�ڲ�����
	bool clrSoftBP(DWORD dwAddress, unsigned char* szBackCode)
	{
		return WriteMemory(m_hProcess, (LPVOID)dwAddress, szBackCode, 2, NULL);
	}

	//����CC�ϵ�
	bool setSoftCC(DWORD dwAddress, unsigned char& szOriCode)
	{
		UCHAR int3 = 0xCC;

		//1. ����
		ReadProcessMemory(m_hProcess, (LPVOID)dwAddress, &szOriCode, 1, NULL);
		//2. �޸�
		return WriteMemory(m_hProcess, (LPVOID)dwAddress, &int3, 1, NULL);
	}
	//���CC�ϵ�
	bool clrSoftCC(DWORD dwAddress, unsigned char& szOriCode)
	{
		//2. �޸�
		return WriteMemory(m_hProcess, (LPVOID)dwAddress, &szOriCode, 1, NULL);
	}

protected:
	//ԭ����һ����ַ����ͬʱ������ϵ��Ӳ�ϵ�, ���ٴ���ĸ��Ӷ�, ��ֵַ������Ϊkey
	std::map<DWORD, tagBP> m_mapBps;
	HANDLE m_hProcess;    //���̾��
	HANDLE m_hThread;     //�߳̾��
};

