

//�¶ϵ�--�ڲ�����
void BP(HANDLE hProcess, DWORD dwAddress)
{
	UCHAR szHalt[] = { 0xEB, 0xFE };
	DWORD dwRead;
	ReadMemory(hProcess, dwAddress, g_szBackCode, 2, &dwRead);
	WriteMemory(hProcess, (LPVOID)dwAddress, szHalt, 2, &dwRead);
}

//��ϵ�--�ڲ�����
void BC(HANDLE hProcess, DWORD dwAddress)
{
	UCHAR szHalt[] = { 0xEB, 0xFE };
	DWORD dwRead;
	WriteMemory(hProcess, (LPVOID)dwAddress, g_szBackCode, 2, &dwRead);
	//ASSERT(bOk);
}

//���ѿǻ���ʾ��������
void Resume(HANDLE hThread)
{
	//����Ŀ�����
	::ResumeThread(hThread);
}

//���ѿǻ���ʾ��ͣ
CONTEXT Halt(HANDLE hThread)
{
	::SuspendThread(hThread);
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	BOOL bOk = ::GetThreadContext(hThread, &context);
	assert(bOk);
	return context;
}

//��ָ����ַ--�ڲ�����
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
		context = Halt(hThread);			//��ͣ����
		dwCurEip = context.Eip;
	}
	BC(hProcess, dwAddress);
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	bOk = ::GetThreadContext(hThread, &context);
	assert(bOk);
	return true;
}

//�����û�����--�ڲ�����
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

//�ײ���Ϣ��ʵ��
void SendMsg(UINT uMsg, WPARAM wParam, LPARAM lParam, HWND hWnd = g_hWndList)
{
	if (hWnd != NULL)
		::SendMessage(hWnd, uMsg, wParam, lParam);
}

//���ѿǻ���ʾ�����ѿǹ��̲������ʵ�����
void Terminate(HANDLE hProcess, HANDLE hThread)
{
	::CloseHandle(hProcess);
	::CloseHandle(hThread);
	SendMsg(WM_TERMINATE, 0, 0);
}

//���ѿǻ���ʾdump
void DumeNow(DWORD dwIdt = 0, DWORD dwIdtSize = 0)
{
	SendMsg(WM_DUMPNOW, (WPARAM)dwIdt, (LPARAM)dwIdtSize);
}

//���ѿǻ������ַ���
void TellUnpacker(std::string strMsg)
{
	::ZeroMemory(g_szNewMsg, 256);
	strcat(g_szNewMsg, g_szAboutMe);
	strcat(g_szNewMsg, strMsg.c_str());
	static    char   *pStr = g_szNewMsg;
	SendMsg(WM_SENDSTRING, (WPARAM)pStr, 0);
}

//���ڲ��--API
extern "C" void WINAPI AboutPlugin()
{
	TellUnpacker(g_szVersion);
}
