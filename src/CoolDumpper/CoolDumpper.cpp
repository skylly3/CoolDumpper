#include "stdafx.h"
#include "../undoc.h"
#include "CoolDumpper.h"
#include <tlhelp32.h>
#include <CommCtrl.h>   //listview控件
#include <commdlg.h>   //打开文件对话框
#include <shellapi.h>	//dragaccept file
#include <algorithm>  //transform
#include <string>
#include <vector>

#include "../disasm/disasm.h"


#include "../debugger.h"

#define MAX_LOADSTRING 100

std::wstring m_strPluginPath;					 //插件完整路径
HMODULE m_hModPlugin = nullptr;                  //插件句柄
typedef void (WINAPI *InitPluginFunc)(HWND);
typedef void (WINAPI *AboutPluginFunc)();
typedef void (WINAPI *StartUnpackFunc)(PROCESS_INFORMATION, DWORD, DWORD);
StartUnpackFunc startUnpackFunc = nullptr;		  //脱壳函数

HMODULE m_hModDisam = nullptr;					  //disam插件句柄
pfnDisasm pDisasm = nullptr;					  //disam函数

#if 0
HMODULE m_hModImprec = nullptr;					  //imprec插件句柄
typedef BOOL(WINAPI * pfnRebuildImport)(DWORD pid, DWORD oep_rva, DWORD iat_rva, DWORD nb_recursion, LPSTR dump_filename);
pfnRebuildImport pRebuildImport = nullptr;

typedef DWORD(WINAPIV *pfnSetModule)(DWORD pid, DWORD base);
typedef void (WINAPIV *pfnLogIATEntry)(DWORD rva_iat_slot, DWORD va_api);
typedef DWORD(WINAPIV *pfnMakeImportTable)(LPSTR dump_filename);
pfnSetModule pSetModule = nullptr;				  //setModule函数
pfnLogIATEntry pLogIATEntry = nullptr;
pfnMakeImportTable pMakeImportTable = nullptr;	  //MakeImportTable函数

#else

typedef int(_stdcall *_UIF)(LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, bool);
_UIF UIF;

typedef int(_stdcall* ScyllaIatFixAutoW)(DWORD_PTR iatAddr, DWORD iatSize, DWORD dwProcessId, const WCHAR * dumpFile, const WCHAR * iatFixFile);
ScyllaIatFixAutoW fixiat;

#endif

// 全局变量:
HINSTANCE hInst = nullptr;		   // 当前实例
HWND m_hWnd = nullptr;			   // 主窗口句柄
HWND m_hWindList = nullptr;        // 进程列表句柄
DWORD m_dwImageBase = 0;		   // 模块基地址
DWORD m_dwCodeBase = 0;			   // 代码基地址
DWORD m_dwEpRva = 0;			   // 当前入口点
PROCESS_INFORMATION m_pi;		   // 脱壳进程信息



#include <iostream>
std::wstring CA2CT(const char* mbstr, UINT codepage)
{
	std::wstring str = L"";
	// 计算需要的缓冲区大小（以宽字符为单位）
	int requiredSize = MultiByteToWideChar(codepage, 0, mbstr, -1, NULL, 0);

	if (requiredSize == 0) {
		// 失败处理
		std::cerr << "MultiByteToWideChar failed." << std::endl;
		return str;
	}

	// 分配缓冲区
	wchar_t* wcstr = new wchar_t[requiredSize];

	// 进行转换
	if (MultiByteToWideChar(codepage, 0, mbstr, -1, wcstr, requiredSize) == 0) {
		// 失败处理
		std::cerr << "MultiByteToWideChar failed." << std::endl;
		delete[] wcstr;
		return str;
	}

	// 输出转换后的 Unicode 字符串
	str = wcstr;

	// 释放缓冲区
	delete[] wcstr;

	return str;
}

std::string CT2CA(const wchar_t* unicodeString, UINT codepage)
{
	std::string str = "";
	// 计算需要的缓冲区大小（以宽字符为单位）
	int requiredSize = WideCharToMultiByte(codepage, 0, unicodeString, -1, NULL, 0, NULL, NULL);

	if (requiredSize == 0) {
		// 失败处理
		std::cerr << "WideCharToMultiByte failed." << std::endl;
		return str;
	}

	// 分配缓冲区
	char* gbkString = new char[requiredSize];

	// 进行转换
	if (WideCharToMultiByte(codepage, 0, unicodeString, -1, gbkString, requiredSize, NULL, NULL) == 0) {
		// 失败处理
		std::cerr << "WideCharToMultiByte failed." << std::endl;
		delete[] gbkString;
		return str;
	}

	// 输出转换后的 Unicode 字符串
	str = gbkString;

	// 释放缓冲区
	delete[] gbkString;

	return str;
}

struct ShellInfo {
	std::wstring section;     //壳名称
	std::string signature;    //壳特征字符串
	bool bEpOnly;			  //从入口点开始查找
	bool bIsCompile;          //是编译器,不是壳
};
//壳特征码列表 从ep开始搜索
std::vector<ShellInfo> g_shellEp;
//壳特征码列表 整个代码段搜索
std::vector<ShellInfo> g_shellEntry;
//编译器特征码列表 整个代码段搜索
std::vector<ShellInfo> g_shellCompile;

bool ReadConfigFile(const std::string& filename, std::vector<ShellInfo>& shellEp, std::vector<ShellInfo>& shellEntry) {
	const int bufferSize = 102400; // 适当大小的缓冲区 100k
	char* buffer = new char[bufferSize];

	// 读取配置文件中的section名称
	DWORD bytesRead = GetPrivateProfileSectionNamesA(buffer, bufferSize, filename.c_str());
	if (bytesRead == 0) {
		// 读取失败
		delete[] buffer;
		return false;
	}
	const char* ptr = buffer;
	while (*ptr != '\0')
	{
		std::string sectionName(ptr);

		// 读取signature项
		char szSign[2048];
		GetPrivateProfileStringA(sectionName.c_str(), "signature", "", szSign, 2048, filename.c_str());

		// 读取ep_only项
		char szEponly[10];
		GetPrivateProfileStringA(sectionName.c_str(), "ep_only", "", szEponly, 10, filename.c_str());
		bool ep_only = _strcmpi(szEponly, "true") == 0;

		ShellInfo entry;
		entry.section = CA2CT(sectionName.c_str(), CP_ACP);
		entry.signature = std::string(szSign);
		entry.bEpOnly = ep_only;
		entry.bIsCompile = false;
		if (ep_only)
			shellEp.push_back(entry);    //从ep开始搜索
		else
			shellEntry.push_back(entry); //整个代码段搜索

		// 移动指针到下一个section的名称
		ptr += sectionName.size() + 1;
	}
	delete[] buffer;

	return !(shellEp.empty() && shellEntry.empty());
}

// “关于”框的消息处理程序。
INT_PTR CALLBACK AboutWndProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

// 向列表中的添加列
VOID InsertListViewColumns(HWND hWindList)
{
	// 1. 初始化一个列结构体进行设置
	// 1.1 第一个字段 mask 表示想要应用哪些设置(对齐方式，文字，宽度)
	LVCOLUMN lvColumn = { LVCF_FMT | LVCF_TEXT | LVCF_WIDTH };
	// 1.2 设置对齐方式，第一列的对其方式始终是左对齐
	lvColumn.fmt = LVCFMT_LEFT;
	// 2.设置列名并添加列
	lvColumn.cx = 100;
	lvColumn.pszText = (LPWSTR)L"PID";
	ListView_InsertColumn(hWindList, 0, &lvColumn);

	lvColumn.cx = 150;
	lvColumn.pszText = (LPWSTR)L"Process Name";
	ListView_InsertColumn(hWindList, 1, &lvColumn);

	lvColumn.cx = 320;
	lvColumn.pszText = (LPWSTR)L"Path";
	ListView_InsertColumn(hWindList, 2, &lvColumn);
}

// 添加数据到某一行
VOID InsertListViewItem(HWND hListView, int index, LPCWSTR strPid, LPCWSTR Name, LPCWSTR Path)
{
	// 1. 先添加一行数据，并且设置第一列的信息
	LVITEM lvItem = { LVIF_TEXT };
	lvItem.iItem = index;
	lvItem.pszText = (LPWSTR)strPid;
	ListView_InsertItem(hListView, &lvItem);
	ListView_SetItemText(hListView, index, 1, (LPWSTR)Name);
	ListView_SetItemText(hListView, index, 2, (LPWSTR)Path);
}

bool GetItemText(HWND hListView, int row, int col, std::wstring& sText)
{
	LVITEM lvItem;
	lvItem.mask = LVIF_TEXT;
	lvItem.iItem = row; // 或者当前循环的索引
	lvItem.iSubItem = col; // 获取第一个子项的文本
	lvItem.cchTextMax = MAX_PATH; // 缓冲区大小
	lvItem.pszText = new TCHAR[MAX_PATH]; // 分配缓冲区
	bool bRet = false;
	if (ListView_GetItem(m_hWindList, &lvItem)) {
		sText = lvItem.pszText;
		bRet = true;
	}
	delete[] lvItem.pszText;
	return bRet;
}

//设置调试权限
#include <Windows.h>

int setDebugPrivilege() {
	// 获取当前进程的句柄
	HANDLE hProcess = GetCurrentProcess();

	// 获取当前进程的访问令牌
	HANDLE hToken;
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		// 定义一个特权数组，这里我们添加调试特权
		TOKEN_PRIVILEGES tokenPrivileges;
		tokenPrivileges.PrivilegeCount = 1;
		tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		// 查找调试特权的LUID（本地唯一标识符）
		if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid)) {
			// 调整访问令牌的特权
			if (AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
				if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
					std::cerr << "Failed to enable debug privilege." << std::endl;
				}
				else {
					std::cout << "Debug privilege enabled successfully." << std::endl;
				}
			}
			else {
				std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
			}
		}
		else {
			std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
		}

		// 关闭令牌句柄
		CloseHandle(hToken);
	}
	else {
		std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
	}

	return 0;
}

//std::wstring format(std::wstring sFormat, DWORD dwNum)
//{
//	WCHAR szOut[100];
//	wsprintf(szOut, sFormat.c_str(), dwNum);
//	std::wstring str = szOut;
//	return str;
//}
//std::wstring format(std::wstring sFormat, DWORD dwNum, DWORD dwNum2)
//{
//	WCHAR szOut[100];
//	wsprintf(szOut, sFormat.c_str(), dwNum, dwNum2);
//	std::wstring str = szOut;
//	return str;
//}

//std::string format(const char* sFormat, DWORD dwNum, char* str1, char* str2)
//{
//	CHAR szOut[100];
//	sprintf(szOut, sFormat, dwNum, str1, str2);
//	std::string str = szOut;
//	return str;
//}

std::string format(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char buf[2048];
	vsprintf(buf, fmt, ap);
	va_end(ap);
	std::string str = std::string(buf);
	return str;
}


std::wstring format(const wchar_t* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	wchar_t buf[2048];
	vswprintf(buf, 2048, fmt, ap);
	va_end(ap);
	std::wstring str = std::wstring(buf);
	return str;
}

//std::string format(const char* sFormat, char* str1, char* str2)
//{
//	CHAR szOut[100];
//	sprintf(szOut, sFormat, str1, str2);
//	std::string str = szOut;
//	return str;
//}

void OutText(std::wstring str)
{
	HWND hEdit = GetDlgItem(m_hWnd, IDC_EDIT_MSG);
	int len = GetWindowTextLength(hEdit);
	SendMessageW(hEdit, EM_SETSEL, len, len);  // 设置插入点到文本末尾

	str += L"\r\n";
	SendMessageW(hEdit, EM_REPLACESEL, 0, (LPARAM)str.c_str());  // 追加文本
}

void ClearLog()
{
	HWND hEdit = GetDlgItem(m_hWnd, IDC_EDIT_MSG);
	int len = GetWindowTextLength(hEdit);
	SendMessageW(hEdit, EM_SETSEL, 0, len);  // 设置插入点到文本末尾

	std::wstring str = L"";
	SendMessageW(hEdit, EM_REPLACESEL, 0, (LPARAM)str.c_str());  // 追加文本
}

// 将 RVA 转换成实际的数据位置
DWORD RVA2Offset(LPVOID pFileHead, DWORD dwRVA)
{
	DWORD dwOffset = 0;

	IMAGE_DOS_HEADER * pIDH = (IMAGE_DOS_HEADER *)pFileHead;
	LPVOID pNTHeader = (char *)pFileHead + pIDH->e_lfanew;
	IMAGE_NT_HEADERS * pINH = (IMAGE_NT_HEADERS *)pNTHeader;

	// 得到节表位置
	IMAGE_SECTION_HEADER * pISH = (IMAGE_SECTION_HEADER *)((char *)pINH + sizeof(IMAGE_NT_HEADERS));
	int nSecCount = pINH->FileHeader.NumberOfSections;

	// 扫描每个节区并判断 RVA 是否位于这个节区内
	DWORD dwTmpRva = dwRVA;
	for (int i = 0; i < nSecCount; i++)
	{
		DWORD dwSectionEnd = pISH->VirtualAddress + pISH->SizeOfRawData;
		if ((dwTmpRva >= pISH->VirtualAddress) && (dwTmpRva < dwSectionEnd))
		{

			dwTmpRva -= pISH->VirtualAddress; // dwTmpRva = offset in section
			dwOffset = pISH->PointerToRawData + dwTmpRva; // file offset
			break;
		}
		pISH++;
	}

	return dwOffset;
}

char GetHexValue(const std::string& strHex, int pos)
{
	assert(strHex.length() >= pos * 3 + 1);

	char hexchar[3];
	hexchar[0] = strHex[pos * 3];
	hexchar[1] = strHex[pos * 3 + 1];
	hexchar[2] = 0;

	int iValue = strtol(hexchar, NULL, 16);
	return iValue;
}

bool DetectShell(const char* pCodeBase, const DWORD dwCodeSize, const char* pEntryPoint, const std::string& sSign, bool bEpOnly, int& iFindOff)
{
	char ch1, ch2;
	bool bFindShell = true;
	//要检查的字节长度
	int len = (sSign.length() + 1) / 3;
	if (bEpOnly)
	{//从ep开始检查
		for (int i = 0; i < len; i++)
		{
			ch1 = *(pEntryPoint + i);
			if (sSign.substr(i * 3, 2) == "??")
				continue;  //万能匹配符号

			ch2 = GetHexValue(sSign, i);
			if (ch1 != ch2)
			{//一票否决
				bFindShell = false;
				break;
			}
		}
		if (bFindShell)
			iFindOff = pEntryPoint - pCodeBase;
	}
	else
	{
		for (int iOffset = 0; (iOffset + len) < dwCodeSize; iOffset++)
		{
			bFindShell = true;
			for (int i = 0; i < len; i++)
			{
				ch1 = *(pCodeBase + iOffset + i);
				if (sSign.substr(i * 3, 2) == "??")
					continue;  //万能匹配符号
				ch2 = GetHexValue(sSign, i);
				if (ch1 != ch2)
				{//一票否决
					bFindShell = false;
					break;
				}
			}
			if (bFindShell)
			{//找到了匹配的
				iFindOff = iOffset;
				break;
			}
		}
	}
	return bFindShell;
}

std::string GetCurrentDirA() {
	CHAR szPath[MAX_PATH];
	::GetModuleFileNameA(nullptr, szPath, MAX_PATH);

	// 从完整路径中提取目录部分
	std::string currentDirectory(szPath);
	int lastIndex = currentDirectory.rfind('\\');
	if (lastIndex != -1) {
		currentDirectory = currentDirectory.substr(0, lastIndex);
	}

	return currentDirectory;
}
std::wstring GetCurrentDir() {
	TCHAR szPath[MAX_PATH];
	::GetModuleFileName(nullptr, szPath, MAX_PATH);

	// 从完整路径中提取目录部分
	std::wstring currentDirectory(szPath);
	int lastIndex = currentDirectory.rfind('\\');
	if (lastIndex != -1) {
		currentDirectory = currentDirectory.substr(0, lastIndex);
	}

	return currentDirectory;
}

//插件初始化
void OnCbnSelchangeCmPlug()
{
	if (m_hModPlugin)
	{
		FreeLibrary(m_hModPlugin);
		m_hModPlugin = nullptr;
	}
	TCHAR szPlugName[MAX_PATH];
	GetDlgItemText(m_hWnd, IDC_CM_PLUG, szPlugName, MAX_PATH);
	if (lstrcmp(szPlugName, L"调试模式") == 0)
	{
		ShowWindow(GetDlgItem(m_hWnd, IDC_CHECK_OEP), SW_SHOW);
		ShowWindow(GetDlgItem(m_hWnd, IDC_EDIT_OEP), SW_SHOW);
		ShowWindow(GetDlgItem(m_hWnd, IDC_BTN_FINDOEP), SW_SHOW);
		ShowWindow(GetDlgItem(m_hWnd, IDC_BTN_CODE), SW_SHOW);

		ShowWindow(GetDlgItem(m_hWnd, IDC_CHECK_HOOKAPI), SW_SHOW);
		ShowWindow(GetDlgItem(m_hWnd, IDC_CMB_HOOKAPI), SW_SHOW);
		return;
	}
	else if (lstrcmp(szPlugName, L"给力模式") == 0)
	{
		ShowWindow(GetDlgItem(m_hWnd, IDC_CHECK_OEP), SW_HIDE);
		ShowWindow(GetDlgItem(m_hWnd, IDC_EDIT_OEP), SW_HIDE);
		ShowWindow(GetDlgItem(m_hWnd, IDC_BTN_FINDOEP), SW_HIDE);
		ShowWindow(GetDlgItem(m_hWnd, IDC_BTN_CODE), SW_HIDE);

		ShowWindow(GetDlgItem(m_hWnd, IDC_CHECK_HOOKAPI), SW_SHOW);
		ShowWindow(GetDlgItem(m_hWnd, IDC_CMB_HOOKAPI), SW_SHOW);
		return;
	}
	else
	{//插件模式
		ShowWindow(GetDlgItem(m_hWnd, IDC_CHECK_OEP), SW_HIDE);
		ShowWindow(GetDlgItem(m_hWnd, IDC_EDIT_OEP), SW_HIDE);
		ShowWindow(GetDlgItem(m_hWnd, IDC_BTN_FINDOEP), SW_HIDE);
		ShowWindow(GetDlgItem(m_hWnd, IDC_BTN_CODE), SW_HIDE);

		ShowWindow(GetDlgItem(m_hWnd, IDC_CHECK_HOOKAPI), SW_HIDE);
		ShowWindow(GetDlgItem(m_hWnd, IDC_CMB_HOOKAPI), SW_HIDE);
	}
	if (!m_hModPlugin)
	{
		m_strPluginPath = GetCurrentDir();
		m_strPluginPath += L"\\plugin\\";
		m_strPluginPath += szPlugName;
		m_hModPlugin = LoadLibrary(m_strPluginPath.c_str());
	}
	if (!m_hModPlugin)
		OutText(L"加载模块失败");
	else
	{
		// 2. 获取函数指针
		FARPROC pInitPlugin = GetProcAddress(m_hModPlugin, "InitPlugin");

		if (pInitPlugin != nullptr) {
			// 3. 调用函数
			InitPluginFunc initPluginFunc = reinterpret_cast<InitPluginFunc>(pInitPlugin);
			initPluginFunc(m_hWnd); // 调用AboutPlugin函数
		}
		else {
			OutText(L"Failed to get pInitPlugin pointer.");
		}


		FARPROC pStartUnpack = GetProcAddress(m_hModPlugin, "StartUnpack");

		if (pStartUnpack != nullptr) {
			// 3. 调用函数

			startUnpackFunc = reinterpret_cast<StartUnpackFunc>(pStartUnpack);
		}
		else {
			OutText(L"Failed to get pStartUnpack pointer.");
		}
	}
}

std::wstring _GetShell(const std::wstring& _FileName)
{
	std::wstring strShell(L"");
	HANDLE hMapping;					//handle for the mapping file detecting
	void *pBasePointer;					//pointer for the mapping file begin
	IMAGE_DOS_HEADER *imDos_Headers;	//定义DOS头
	IMAGE_NT_HEADERS *imNT_Headers;		//定义PE头
	HANDLE hFile = CreateFile(_FileName.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);		//Create the File handle
	if (hFile == INVALID_HANDLE_VALUE)
	{	//test File Handle
		DWORD dwError = GetLastError();
		CloseHandle(hFile);
		strShell = format(L"文件打开失败,错误代码为:%u", dwError);
		return strShell;
	}

	if (!(hMapping = CreateFileMapping(hFile, 0, PAGE_READONLY | SEC_COMMIT, 0, 0, 0)))
	{									//Create the File Map and test
		DWORD dwError = GetLastError();
		CloseHandle(hFile);
		CloseHandle(hMapping);
		strShell = format(L"创建文件映射失败,错误代码为:%u", dwError);
		return strShell;
	}

	if (!(pBasePointer = ::MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)))
	{
		DWORD dwError = GetLastError();
		UnmapViewOfFile(pBasePointer);
		CloseHandle(hFile);
		CloseHandle(hMapping);
		strShell = format(L"映射文件失败,错误代码为:%u", dwError);
		return strShell;
	}

	imDos_Headers = (IMAGE_DOS_HEADER *)pBasePointer;	//设置初始指针地址
	if (imDos_Headers->e_magic != IMAGE_DOS_SIGNATURE)
	{
		UnmapViewOfFile(pBasePointer);
		CloseHandle(hFile);
		CloseHandle(hMapping);
		strShell = (L"不是PE文件!");
		return strShell;
	}
	imNT_Headers = (IMAGE_NT_HEADERS *)((char *)pBasePointer + imDos_Headers->e_lfanew);//NT头指针地址
	//PE文件EP
	const char* pEntryPoint = ((const char*)pBasePointer + RVA2Offset(pBasePointer, imNT_Headers->OptionalHeader.AddressOfEntryPoint));

	//从ep开始查找
	for (int i = 0; i < g_shellEp.size(); i++)
	{
		const char* pBaseCode = (const char*)pBasePointer + RVA2Offset(pBasePointer, imNT_Headers->OptionalHeader.BaseOfCode);
		DWORD dwSizeCode = imNT_Headers->OptionalHeader.SizeOfCode;

		int iFindOff = 0;
		if (DetectShell(pBaseCode, dwSizeCode, pEntryPoint, g_shellEp[i].signature, g_shellEp[i].bEpOnly, iFindOff))
		{
			strShell = g_shellEp[i].section;
			break;
		}
	}
	//整个代码段查找
	if (strShell.empty())
	{
		for (int i = 0; i < g_shellEntry.size(); i++)
		{
			const char* pBaseCode = (const char*)pBasePointer + RVA2Offset(pBasePointer, imNT_Headers->OptionalHeader.BaseOfCode);
			DWORD dwSizeCode = imNT_Headers->OptionalHeader.SizeOfCode;

			int iFindOff = 0;
			if (DetectShell(pBaseCode, dwSizeCode, pEntryPoint, g_shellEntry[i].signature, g_shellEntry[i].bEpOnly, iFindOff))
			{
				strShell = g_shellEntry[i].section;
				break;
			}
		}
	}


	if (strShell.empty())
	{
		strShell = L"未检测到!:(";
	}
	else
	{//自动选壳
		HWND hCmbPlug = GetDlgItem(m_hWnd, IDC_CM_PLUG);
		int itemCount = SendMessage(hCmbPlug, CB_GETCOUNT, 0, 0);

		for (int i = 0; i < itemCount; i++)
		{
			//枚举combobox文本
			wchar_t itemText[256];
			SendMessage(hCmbPlug, CB_GETLBTEXT, i, (LPARAM)itemText);
			std::wstring sText = itemText;
			std::wstring sExtern = sText.substr(sText.length() - 4, 4);
			if (lstrcmpi(sExtern.c_str(), L".dll") == 0)
			{
				std::wstring sPluginName = sText.substr(0, sText.length() - 4);
				transform(sPluginName.begin(), sPluginName.end(), sPluginName.begin(), ::toupper);
				//壳名称转换成大写
				std::wstring wstrShell = strShell;
				transform(wstrShell.begin(), wstrShell.end(), wstrShell.begin(), ::toupper);
				if (strShell.find(sPluginName) != -1)
				{
					SendMessage(hCmbPlug, CB_SETCURSEL, i, 0);
					OnCbnSelchangeCmPlug();
					std::wstring strInfo = L"自动选择脱壳插件:";
					strInfo += sText;
					OutText(strInfo);
					break;
				}
			}
		}
	}

	UnmapViewOfFile(pBasePointer);
	CloseHandle(hMapping);
	CloseHandle(hFile);

	return strShell;
}

#include <psapi.h>
#pragma comment(lib, "psapi.lib")   //GetModuleFileNameExW
std::wstring GetProcPath(DWORD IDProcess)
{
	std::wstring szRet = L"";
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, IDProcess);
	if (hProcess != NULL) {
		//DWORD dwBufLen = MAX_PATH;
		//TCHAR szFullPath[MAX_PATH] = {0};
		//QueryFullProcessImageName(hProcess, 0, szFullPath, &dwBufLen);

		wchar_t processPath[MAX_PATH] = { 0 };
		BOOL result = GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH);
		CloseHandle(hProcess);

		szRet = processPath;
	}
	return szRet;
}

//枚举进程列表后添加到列表上
BOOL GetProcessListFunc(HWND hDlg, HWND hWindList)
{
	//此函数是进程列表的作用，在此不作过多介绍
	PROCESSENTRY32 pe32 = { 0 };
	SendMessage(hWindList, LB_RESETCONTENT, 0, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	//清空所有数据
	SendMessage(hWindList, LVM_DELETEALLITEMS, 0, 0);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	int index = 0;
	do
	{
		std::wstring szFullPath = GetProcPath(pe32.th32ProcessID);
		InsertListViewItem(hWindList, index++, format(L"%d", pe32.th32ProcessID).c_str(), pe32.szExeFile, szFullPath.c_str());
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);

	return TRUE;
}


#include <iostream>
#include <fstream>

bool GetFileEp(const std::wstring& strFileName, DWORD& dwImageBase, DWORD& dwCodeBase, DWORD& dwEpRva) {
	// 打开PE文件，使用wifstream
	std::ifstream file(strFileName, std::ios::binary);
	if (!file) {
		std::wcerr << L"Failed to open PE file." << std::endl;
		return false;
	}

	// 读取DOS头
	IMAGE_DOS_HEADER dosHeader;
	file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		std::wcerr << L"Not a valid DOS executable." << std::endl;
		file.close();
		return false;
	}

	// 移动文件指针到PE文件头
	file.seekg(dosHeader.e_lfanew, std::ios::beg);

	// 读取PE文件头
	IMAGE_NT_HEADERS ntHeaders;
	file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
		std::wcerr << L"Not a valid PE file." << std::endl;
		file.close();
		return false;
	}

	// 获取入口点地址
	dwImageBase = ntHeaders.OptionalHeader.ImageBase;
	dwEpRva = ntHeaders.OptionalHeader.AddressOfEntryPoint;
	dwCodeBase = ntHeaders.OptionalHeader.BaseOfCode;
	std::wcout << L"Entry Point Address: 0x" << std::hex << dwEpRva << std::endl;

	// 关闭文件
	file.close();
	return true;
}

void LoadFile(const std::wstring& sFileName)
{
	SetWindowText(GetDlgItem(m_hWnd, IDC_EDIT_FILENAME), sFileName.c_str());

	GetFileEp(sFileName, m_dwImageBase, m_dwCodeBase, m_dwEpRva);


	if (m_dwImageBase != 0)
	{
		std::wstring strEp = format(L"模块基地址:%08x", m_dwImageBase);
		OutText(strEp);
	}

	if (m_dwEpRva != 0)
	{
		std::wstring strEp = format(L"当前入口点:%08x", m_dwEpRva);
		OutText(strEp);
	}
	else
	{
		OutText(L"获取入口点失败");
	}
	//检查加壳信息
	std::wstring strShell = _GetShell(sFileName);
	OutText(std::wstring(L"检测到壳特征:") + strShell);
}

//粘贴原始文件中的PE头
BOOL CopyThePEHead(HWND hDlg, DWORD dwPID, LPCTSTR Dump_Name, const DWORD dwOepRva)
{
	//此函数的作用是将原来PE文件的PE头部完整的copy到dump文件中
	HANDLE hFile = CreateFile(GetProcPath(dwPID).c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD dwErr = GetLastError();
		dwErr = dwErr;
		MessageBox(hDlg, TEXT("I can open the object file..."), TEXT("Error!!"), MB_OK | MB_ICONWARNING);
		return FALSE;
	}
	//下面移动到节表前面
	IMAGE_DOS_HEADER myDosHeader;
	DWORD NumberOfBytesReadorWrite;
	BOOL bRead = ReadFile(hFile, (LPVOID)&myDosHeader, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesReadorWrite, NULL);
	SetFilePointer(hFile, myDosHeader.e_lfanew + sizeof(DWORD), NULL, FILE_BEGIN);
	IMAGE_FILE_HEADER myNtHeader;
	bRead = ReadFile(hFile, (LPVOID)&myNtHeader, sizeof(IMAGE_FILE_HEADER), &NumberOfBytesReadorWrite, NULL);
	IMAGE_SECTION_HEADER mySectionHeader;
	SetFilePointer(hFile, myDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), NULL, FILE_BEGIN);
	bRead = ReadFile(hFile, (LPVOID)&mySectionHeader, sizeof(IMAGE_SECTION_HEADER), &NumberOfBytesReadorWrite, NULL);
	SetFilePointer(hFile, NULL, NULL, FILE_BEGIN);
	HGLOBAL hMem = 0;
	//读出节表的第一个文件位置，以确PE头的大小
	//申请同样大小的空间
	hMem = GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, mySectionHeader.PointerToRawData);
	if (!hMem)
	{
		MessageBox(hDlg, TEXT("I can't get the Memory space!"), TEXT("Error!!!"), MB_OK | MB_ICONSTOP);
		return FALSE;
	}
	//将文件中的PE头部读取到申请的空间中
	bRead = ReadFile(hFile, hMem, mySectionHeader.PointerToRawData, &NumberOfBytesReadorWrite, NULL);
	CloseHandle(hFile);
	//////////////////上面是读///////////////////////
	//////////////////下面是写///////////////////////
	hFile = CreateFile(Dump_Name, GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		DWORD dwErr = GetLastError();
		dwErr = dwErr;
		GlobalFree(hMem);
		MessageBox(hDlg, TEXT("I can open the dump file..."), TEXT("Error!!"), MB_OK | MB_ICONWARNING);

		return FALSE;
	}

	if (dwOepRva != 0)
	{//修正OEP  AddressOfEntryPoint
		*(DWORD*)((char*)hMem + myDosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 16) = dwOepRva;
	}
	//下面是将空间中的数据写到dump文件的头部
	WriteFile(hFile, hMem, mySectionHeader.PointerToRawData, &NumberOfBytesReadorWrite, NULL);
	CloseHandle(hFile);
	GlobalFree(hMem);
	return TRUE;
}

//修复节表，按内存中的大小对齐
BOOL ModifySectionFunc(HWND hDlg, LPCTSTR Dump_Name)
{
	//此函数的将修改dump下来的exe，使其RA=RVA ，RS=RVS
	//首先是打开dump文件
	HANDLE hFile = CreateFile(Dump_Name, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{

		MessageBox(hDlg, TEXT("I can open the dump file..."), TEXT("Error!!"), MB_OK | MB_ICONWARNING);
		return FALSE;
	}
	//下面移动到节表前面
	IMAGE_DOS_HEADER myDosHeader;
	DWORD NumberOfBytesReadorWrite;
	ReadFile(hFile, (LPVOID)&myDosHeader, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesReadorWrite, NULL);
	SetFilePointer(hFile, myDosHeader.e_lfanew + sizeof(DWORD), NULL, FILE_BEGIN);
	IMAGE_FILE_HEADER myNtHeader;
	ReadFile(hFile, (LPVOID)&myNtHeader, sizeof(IMAGE_FILE_HEADER), &NumberOfBytesReadorWrite, NULL);
	int nSectionCount;
	nSectionCount = myNtHeader.NumberOfSections;             // 保存Section个数
	// 过了IMAGE_NT_HEADERS结构就是IMAGE_SECTION_HEADER结构数组了，注意是结构数组，有几个Section该结构就有几个元素
	// 这里动态开辟NumberOfSections个内存来存储不同的Section信息
	IMAGE_SECTION_HEADER *pmySectionHeader = (IMAGE_SECTION_HEADER *)calloc(nSectionCount, sizeof(IMAGE_SECTION_HEADER));
	SetFilePointer(hFile, myDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), NULL, FILE_BEGIN);
	ReadFile(hFile, (LPVOID)pmySectionHeader, sizeof(IMAGE_SECTION_HEADER)*nSectionCount, &NumberOfBytesReadorWrite, NULL);
	//移动回到节表的开始，准备写入
	SetFilePointer(hFile, myDosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), NULL, FILE_BEGIN);
	for (int i = 0; i < nSectionCount; i++, pmySectionHeader++)
	{
		//将RA=RVA ，RS=RVS
		pmySectionHeader->SizeOfRawData = pmySectionHeader->Misc.VirtualSize;
		pmySectionHeader->PointerToRawData = pmySectionHeader->VirtualAddress;
		//将修改好的数值写回
		WriteFile(hFile, (LPVOID)pmySectionHeader, sizeof(IMAGE_SECTION_HEADER), &NumberOfBytesReadorWrite, NULL);
	}
	// 恢复指针
	pmySectionHeader -= nSectionCount;

	if (pmySectionHeader != NULL)          // 释放内存
	{
		free(pmySectionHeader);
		pmySectionHeader = NULL;
	}

	// 最后不要忘记关闭文件
	CloseHandle(hFile);
	return TRUE;
}

//创建dump文件
BOOL CreateDumpFile(HWND hDlg, DWORD IDProcess, LPCTSTR Dump_Name, HGLOBAL hMem, const DWORD sizeoffile, const DWORD dwOepRva)
{
	//创建一个新的dump文件
	HANDLE hFile = CreateFile(Dump_Name, GENERIC_WRITE | GENERIC_READ, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{

		MessageBox(hDlg, TEXT("Maybe you have alreadly had a this name file:("), TEXT("Can't create a file"), MB_OK | MB_ICONWARNING);
		GlobalFree(hMem);
		return FALSE;
	}
	int NumberOfBytesWritten;
	WriteFile(hFile, hMem, sizeoffile, (LPDWORD)&NumberOfBytesWritten, NULL);    //注意这个函数第三个参数是必要的！
	CloseHandle(hFile);
	if (!CopyThePEHead(hDlg, IDProcess, Dump_Name, dwOepRva))
	{
		//复制PE头
		MessageBox(hDlg, TEXT("复制PE头失败了"), TEXT("失败了"), MB_OK | MB_ICONWARNING);
	}
	if (!ModifySectionFunc(hDlg, Dump_Name))
	{
		//节表对齐
		MessageBox(hDlg, TEXT("修改节表失败了"), TEXT("失败了"), MB_OK | MB_ICONWARNING);
	}
	//MessageBox(hDlg,TEXT("文件已经dump成功"),TEXT("Lenus'ExeDump"),MB_OK | MB_ICONINFORMATION);//胜利的号角！	
	return TRUE;
}

//#include <Windows.h>
//#include <Psapi.h>
//
//int GetSizeOfImage(HWND hDlg,DWORD dwPID, DWORD& dwBaseAddr)
//{
//    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
//
//    if (hProcess != NULL) {
//        MODULEINFO moduleInfo;
//        if (GetModuleInformation(hProcess, NULL, &moduleInfo, sizeof(MODULEINFO))) {
//            SIZE_T imageSize = moduleInfo.SizeOfImage; // 内存镜像大小
//            std::cout << "进程的内存镜像大小: " << imageSize << " bytes" << std::endl;
//			 CloseHandle(hProcess);
//			return imageSize;
//        } else {
//            std::cerr << "无法获取模块信息" << std::endl;
//        }
//		
//        CloseHandle(hProcess);
//    } else {
//        std::cerr << "无法打开进程" << std::endl;
//    }
//
// 
//    return 0;
//}


int GetSizeOfImage(HWND hDlg, DWORD IDProcess, DWORD& dwBaseAddr)
{
	//这个函数的作用是获取SizeOfImage的数值
	//当函数执行失败返回的是0
	//成功返回的是非0
	HANDLE hModuleSnap = NULL;
	MODULEENTRY32 stModE = { 0 };
	stModE.dwSize = sizeof(MODULEENTRY32);
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, IDProcess);  //快照，对本进程中所有的模块进行snap

	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		MessageBox(hDlg, TEXT("The Module snapshot can't get!"), TEXT("Error!"), MB_OK | MB_ICONSTOP);
		return FALSE;    //返回0
	}
	if (!Module32First(hModuleSnap, &stModE))
	{
		MessageBox(hDlg, TEXT("The Module32First can't work!"), TEXT("Error!"), MB_OK | MB_ICONSTOP);
		CloseHandle(hModuleSnap);
		return FALSE;
	}
	dwBaseAddr = (DWORD)stModE.modBaseAddr;
	CloseHandle(hModuleSnap);
	return stModE.modBaseSize;//初始化为0
}


BOOL CorrectSizeFunc(HWND hDlg, HWND hWindList, DWORD IDProcess, DWORD& sizeofimage)
{
	std::wstring File_Name = GetProcPath(IDProcess);
	if (File_Name.empty())
		return FALSE;
	//打开文件
	HANDLE  hFile;
	hFile = CreateFile(File_Name.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	//创建文件映射内核对象
	HANDLE hMapping;
	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == NULL)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	//创建文件视图
	LPVOID ImageBase;
	ImageBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (ImageBase == NULL)
	{
		CloseHandle(hMapping);
		return FALSE;
	}
	//下面的代码就是从文件的PE头找到SizeOfImage的
	PIMAGE_DOS_HEADER DosHead = NULL;
	PIMAGE_NT_HEADERS32 pNtHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DosHead = (PIMAGE_DOS_HEADER)ImageBase;
	pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)ImageBase + DosHead->e_lfanew);
	pOptionalHeader = &pNtHeader->OptionalHeader;
	sizeofimage = (int)pOptionalHeader->SizeOfImage;

	CloseHandle(hMapping);
	CloseHandle(hFile);
	Sleep(200);
	return TRUE;
}

HGLOBAL ReadProcess(HWND hDlg, HANDLE hProcess, DWORD dwPID, DWORD& dwImageBase, DWORD& dwSizeOfFile)
{
	//此函数是读取目标进程的空间，并把他写入到自己内存空间里面的一个内存块中
	//HANDLE hProcess=OpenProcess(PROCESS_VM_READ,0, dwPID);//使用上面获得的进程id
	if (!hProcess)
	{
		MessageBox(hDlg, TEXT("I can't open the process:("), TEXT("oh my god.."), MB_OK);
		return FALSE;
	}

	//当使用了CorrectSizeFunc后这个有了具体数值，就不需要再次获取了              
	DWORD dwSizeOfImage = GetSizeOfImage(hDlg, dwPID, dwImageBase);   //用Module32First读取内存信息中的镜像大小
	//DWORD dwSizeOfImage = 0;
	//CorrectSizeFunc(m_hWnd, m_hWindList, dwPID, dwSizeOfImage);
	if (dwSizeOfImage == 0)
	{
		CorrectSizeFunc(m_hWnd, m_hWindList, dwPID, dwSizeOfImage);  //读取pe文件中的镜像大小
		if (dwSizeOfImage == 0)
		{
			return FALSE;
		}
	}
	//dump now...
#if 1
	//if (pSetModule)
	//{
	//	pSetModule(m_pi.dwProcessId, dwImageBase);
	//}
#endif
	//为了以防万一，让sizeofimage增加一个文件对齐度。

	if (!(dwSizeOfImage % 0x1000))                          //如果是文件对齐度的整数倍的时候就不处理
		dwSizeOfFile = dwSizeOfImage;
	else
		dwSizeOfFile = (dwSizeOfImage / 0x1000 + 1) * 0x1000;     //如果不是就增加一个文件对齐度

	//申请一个文件空间的内存块
	HGLOBAL hMem = GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, dwSizeOfFile);
	if (!hMem)
	{
		MessageBox(hDlg, TEXT("I think i have enough space to get!:("), TEXT("Wrong!!!"), MB_OK | MB_ICONSTOP);
		return FALSE;
	}
	//将这个pe文件在内存中的大小全部读到申请的块中
	DWORD NumberOfBytesReadorWrite;
	if (!ReadMemory(hProcess, dwImageBase, hMem, dwSizeOfImage, &NumberOfBytesReadorWrite))
	{
		DWORD dwErr = GetLastError();
		dwErr = dwErr;

		GlobalFree(hMem);                    //资源是可贵的，释放空间
		MessageBox(hDlg, TEXT("I can't read the process:("), TEXT("oh my god.."), MB_OK);
		return FALSE;
	}
	return hMem;
}

struct tagDumpPara
{
	std::wstring strSaveName;   //要保存的文件名
	HANDLE hProcess;		    //进程句柄
	HANDLE hThread;             //线程句柄
	DWORD dwOepVA;			    //入口点VA
	DWORD dwIatVA;				//IAt VA
};
tagDumpPara g_dumpPara;

//反汇编代码
void DisasmCode(HWND hWindList, DWORD dwAddress)
{
	if (pDisasm)
	{//反汇编oep处代码
		unsigned char* szBuf = new unsigned char[200];
		DWORD dwRead = 0;
		if (!ReadMemory(g_dumpPara.hProcess, dwAddress, szBuf, 200, &dwRead))
			return;

		SendMessage(hWindList, LVM_DELETEALLITEMS, 0, 0);

		t_disasm da;
		int iOffset = 0;
		for (int i = 0; i < 20; i++)   //反编译20行
		{
			ulong uRet = pDisasm(szBuf + iOffset, 10, dwAddress + iOffset, &da, DISASM_CODE);

			std::wstring strAddr = format(L"%08x", dwAddress + iOffset);
			std::wstring strDump = CA2CT(da.dump, CP_ACP);
			std::wstring strDisasm = CA2CT(da.result, CP_ACP);
			// 1. 先添加一行数据，并且设置第一列的信息
			LVITEM lvItem = { LVIF_TEXT };
			lvItem.iItem = i;
			lvItem.pszText = (LPWSTR)strAddr.c_str();
			ListView_InsertItem(hWindList, &lvItem);
			ListView_SetItemText(hWindList, i, 1, (LPWSTR)strDump.c_str());
			ListView_SetItemText(hWindList, i, 2, (LPWSTR)strDisasm.c_str());

			iOffset += uRet;
		}
		delete[] szBuf;
	}
}

//脱壳对话框的消息处理程序
INT_PTR CALLBACK DumpperWndProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		HWND hWindList = GetDlgItem(hDlg, IDC_LIST_DISASM);
		::SendMessage(hWindList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, (LPARAM)LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
		// 1. 初始化一个列结构体进行设置
		// 1.1 第一个字段 mask 表示想要应用哪些设置(对齐方式，文字，宽度)
		LVCOLUMN lvColumn = { LVCF_FMT | LVCF_TEXT | LVCF_WIDTH };
		// 1.2 设置对齐方式，第一列的对其方式始终是左对齐
		lvColumn.fmt = LVCFMT_LEFT;
		// 2.设置列名并添加列
		lvColumn.cx = 100;
		lvColumn.pszText = (LPWSTR)L"地址";
		ListView_InsertColumn(hWindList, 0, &lvColumn);

		lvColumn.cx = 150;
		lvColumn.pszText = (LPWSTR)L"代码";
		ListView_InsertColumn(hWindList, 1, &lvColumn);

		lvColumn.cx = 200;
		lvColumn.pszText = (LPWSTR)L"反汇编";
		ListView_InsertColumn(hWindList, 2, &lvColumn);

		SetDlgItemText(hDlg, IDC_EDIT_FILENAME, g_dumpPara.strSaveName.c_str());
		std::wstring strText = format(L"%08x", g_dumpPara.dwOepVA);
		SetDlgItemText(hDlg, IDC_EDIT_OEPVA, strText.c_str());
		strText = format(L"%08x", g_dumpPara.dwIatVA);
		SetDlgItemText(hDlg, IDC_EDIT_IATVA, strText.c_str());


		if (g_dumpPara.dwOepVA > 0)
			DisasmCode(hWindList, g_dumpPara.dwOepVA);

		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
	{
		WORD wmId = LOWORD(wParam);
		WORD wmEvent = HIWORD(wParam);
		if (wmId == IDOK || wmId == IDCANCEL)
		{
			if (wmId == IDOK)
			{//确定
				TCHAR strText[MAX_PATH];
				GetDlgItemText(hDlg, IDC_EDIT_FILENAME, strText, MAX_PATH);
				g_dumpPara.strSaveName = strText;

				char szAddr[MAX_PATH];
				GetDlgItemTextA(hDlg, IDC_EDIT_OEPVA, szAddr, MAX_PATH);
				char* szOep = nullptr;
				g_dumpPara.dwOepVA = strtol(szAddr, &szOep, 16);			    //入口点VA

				GetDlgItemTextA(hDlg, IDC_EDIT_IATVA, szAddr, MAX_PATH);
				char* szIat = nullptr;
				g_dumpPara.dwIatVA = strtol(szAddr, &szIat, 16);				//IAt VA
			}

			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		else if (wmId == IDC_BTN_GETEIP)
		{//获取EP
			CONTEXT context;
			context.ContextFlags = CONTEXT_CONTROL;

			if (GetThreadContext(g_dumpPara.hThread, &context))
			{
				std::wstring strPid = format(L"%08x", context.Eip);
				SetDlgItemText(hDlg, IDC_EDIT_OEPVA, strPid.c_str());
			}
			else
			{
				DWORD dwErr = GetLastError();
				dwErr = dwErr;

			}
		}
		else if (wmId == IDC_BTN_CODE)
		{//反汇编代码
			HWND hWindList = GetDlgItem(hDlg, IDC_LIST_DISASM);
			CHAR strText[MAX_PATH];
			GetDlgItemTextA(hDlg, IDC_EDIT_OEPVA, strText, MAX_PATH);

			//创建进程
			char* str = nullptr;
			DWORD dwAddr = strtol(strText, &str, 16);
			DisasmCode(hWindList, dwAddr);
		}
		else if (wmId == IDC_BTN_BROWS)
		{//选择文件
			TCHAR strText[MAX_PATH];
			GetDlgItemText(hDlg, IDC_EDIT_FILENAME, strText, MAX_PATH);

			OPENFILENAME stOF = { 0 };
			stOF.hwndOwner = hDlg;
			stOF.lStructSize = sizeof(stOF);
			stOF.lpstrFilter = L"*.*";
			stOF.lpstrDefExt = L"exe";
			stOF.nMaxFile = MAX_PATH;
			stOF.lpstrFile = strText;
			if (!GetSaveFileNameW(&stOF))
				return (INT_PTR)FALSE;
			SetDlgItemText(hDlg, IDC_EDIT_FILENAME, strText);
		}
	}
	break;
	}
	return (INT_PTR)FALSE;
}

BOOL DumpFunc(HWND hDlg, HANDLE hProcess, HANDLE hThread, DWORD dwPID, DWORD dwOepRVA, const DWORD dwIatRVA)
{
	DWORD dwSizeOfFile = 0;
	HGLOBAL hMem = ReadProcess(hDlg, hProcess, dwPID, m_dwImageBase, dwSizeOfFile);
	if (hMem)                                   //如果返回的hMen不正确说明没有正确的申请到空间
	{
		g_dumpPara.strSaveName = GetCurrentDir() + L"\\dumped.exe";
		g_dumpPara.hProcess = hProcess;
		g_dumpPara.hThread = hThread;
		g_dumpPara.dwOepVA = m_dwImageBase + dwOepRVA;
		g_dumpPara.dwIatVA = m_dwImageBase + dwIatRVA;

		int iRet = DialogBox(hInst, MAKEINTRESOURCE(IDD_DLG_DUMPPER), hDlg, DumpperWndProc);
		if (iRet == IDOK)
		{
			if (dwSizeOfFile != 0)									   //没有大小的dump 是没有意义的
			{
				std::wstring Dump_Name = g_dumpPara.strSaveName;      //要保存的文件名
				if (!Dump_Name.empty())								  //如果得到的文件名是空就不继续执行
				{
					BOOL bOk = CreateDumpFile(hDlg, dwPID, Dump_Name.c_str(), hMem, dwSizeOfFile, g_dumpPara.dwOepVA - m_dwImageBase); //把数据写入文件中

					if (bOk)
					{
						// 假设您有一个ComboBox的句柄（HWND）
						HWND comboBoxHandle = GetDlgItem(m_hWnd, IDC_CM_IAT); // 替换IDC_COMBOBOX为您的ComboBox控件ID
						// 获取当前选中项的索引
						int selectedIndex = SendMessage(comboBoxHandle, CB_GETCURSEL, 0, 0);
						if (selectedIndex == 0)
						{//loader不处理,人工处理
							OutText(L"文件已经保存至:" + Dump_Name);
							MessageBox(m_hWnd, L"请使用第三方工具修复IAT，修复结束前请不要点击\"确定\"按钮!", L"INFO", 0);
						}
						else if (selectedIndex == 1)
						{//调用imprec.dll处理
							std::wstring fix_name = GetCurrentDir() + L"\\dumped_.exe";
							fixiat(g_dumpPara.dwIatVA, 0x1000, m_pi.dwProcessId, Dump_Name.c_str(), fix_name.c_str());

#if 0
							DWORD ProcID = m_pi.dwProcessId, CodeStart = 0, CodeEnd = 0, NewIAT = 0, IATRVA = 0, IATSize = 0, NormImports = 0, DirImports = 0;
							int  Result = UIF(&ProcID, &CodeStart, &CodeEnd, &NewIAT, &IATRVA, &IATSize, &NormImports, &DirImports, FALSE);
							switch (Result)
							{
							case 0:printf("Fixing Success...\n"); break;
							case 1:printf("Error! Process ID is invalid or Process is Protected\n"); break;
							case 2:printf("Process Modules Access Error! maybe Process is Protected\n"); break;
							case 3:printf("Error! Virtual Memory is Low or Invalid 'Code Start','Code End'\n"); break;
							case 4:printf("Memory Access Error! 'Code Start' or 'Code End' is Invalid or Process is Protected\n"); break;
							case 5:printf("Memory Access Error! 'New IAT VA' is Invalid or ReadOnly or Process is Protected\n"); break;
							case 6:printf("Error: WinNt not Present\n"); break;
							case 7:printf("Info: UIF is in Progress\n"); break;
							case 8:printf("Error in Memory Allocation. Enter 'New IAT VA' Manually\n"); break;
							}
							if (Result == 0) printf("IATRVA: %X  , IATSize: %X \n", IATRVA, IATSize);
#endif

#if 0
							//if (pSetModule)
							//{
							//	pSetModule(m_pi.dwProcessId, m_dwImageBase);
							//}

							//if (pLogIATEntry && (g_dumpPara.dwIatVA != 0))
							//{
							//	pLogIATEntry(g_dumpPara.dwIatVA - m_dwImageBase, g_dumpPara.dwIatVA);
							//}

							//if (pMakeImportTable)
							//{//修复输入表
							//	std::string strName = CT2CA(Dump_Name.c_str(), CP_ACP);
							//	DWORD dwRet = pMakeImportTable((LPSTR)strName.c_str());
							//	dwRet = dwRet;
							//}
#endif
#if 0
							if (pRebuildImport)
							{//追踪等级5
								std::string szFile = CT2CA(Dump_Name.c_str(), CP_ACP);
								pRebuildImport(dwPID, dwOepVA - m_dwImageBase, g_dumpPara.dwIatVA - m_dwImageBase, 3, (LPSTR)szFile.c_str());
							}
#endif
						}
						else
						{//插件修复,loader实质不处理

						}

					}//创建dump文件成功
				}//文件名有效
			}//sizeoffile!=0
		}
		else
		{
			OutText(L"用户取消保存");
		}
		GlobalFree(hMem);								//资源是可贵的，释放空间
	}//hMem

	return TRUE;
}

//调试模式启动
void DebugFile(LPCTSTR strFile)
{
	STARTUPINFO startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);
	DEBUG_EVENT debugEvent;
	//创建进程
	if (CreateProcess(strFile, nullptr, NULL, NULL, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &startupInfo, &m_pi))
	{
		OutText(L"CreateProcess success");
		BOOL ProcessExist = TRUE;
		OutText(L"Debug Process Start");
		UpkMgr mgr(m_pi.dwProcessId, m_pi.dwThreadId);
		//hook api的地址
		DWORD dwHookApi = 0;
		bool bHookedApi = false;
		bool bHookedOep = false;
		//调试用的断点类型
		UpkMgr::BP_TYPE bpType = UpkMgr::BT_CC;
		//第一次中断必然是系统的int3断点
		bool bIsSystemInt3 = true;

		//进程创建后监听
		while (ProcessExist)
		{
			if (WaitForDebugEvent(&debugEvent, 1000))
			{
				// OutText(L"WaitForDebugEvent Success");
				switch (debugEvent.dwDebugEventCode)
				{
					//创建进程调试事件
				case CREATE_PROCESS_DEBUG_EVENT:
					OutText(L"CREATE_PROCESS_DEBUG_EVENT");


					break;
					//退出进程调试事件
				case EXIT_PROCESS_DEBUG_EVENT:
					OutText(L"EXIT_PROCESS_DEBUG_EVENT");
					break;
				case LOAD_DLL_DEBUG_EVENT:
				{
					DWORD nNumberOfBytesRead = 0;
					DWORD dwAddrImageName = 0;
					ReadProcessMemory(m_pi.hProcess, debugEvent.u.LoadDll.lpImageName, &dwAddrImageName, sizeof(dwAddrImageName), &nNumberOfBytesRead);
					CHAR DllName[MAX_PATH];
					ReadProcessMemory(m_pi.hProcess, (void*)dwAddrImageName, DllName, sizeof(DllName), &nNumberOfBytesRead);

					std::wstring sDllName = L"";
					std::wstring sOut = L"";
					if (debugEvent.u.LoadDll.fUnicode) {
						sDllName = format(L"%s", DllName);
					}
					else {
						sDllName = CA2CT(DllName, CP_ACP);
					}
					transform(sDllName.begin(), sDllName.end(), sDllName.begin(), ::tolower);
					sOut = format(L"LOAD_DLL_DEBUG_EVENT DLLNAME: %s", sDllName.c_str());
					OutText(sOut);

					if (!bHookedOep && IsDlgButtonChecked(m_hWnd, IDC_CHECK_OEP))
					{//FINDOEP  在找到的OEP处设置一个硬件断点
						char szHookOep[MAX_PATH];
						GetDlgItemTextA(m_hWnd, IDC_EDIT_OEP, szHookOep, MAX_PATH);
						char* str = nullptr;
						DWORD dwOep = strtol(szHookOep, &str, 16);
						bHookedOep = mgr.AddBp(dwOep, bpType, "oep");
					}
				}

				break;
				case UNLOAD_DLL_DEBUG_EVENT:
					OutText(L"UNLOAD_DLL_DEBUG_EVENT");
					break;
					//异常调试事件
				case EXCEPTION_DEBUG_EVENT:
				{
					if (bIsSystemInt3)
					{
						OutText(L"到达系统断点");
						bIsSystemInt3 = false;

						if (!bHookedApi && IsDlgButtonChecked(m_hWnd, IDC_CHECK_HOOKAPI))
						{//HOOKAPI
							char szHookApi[MAX_PATH];
							GetDlgItemTextA(m_hWnd, IDC_CMB_HOOKAPI, szHookApi, MAX_PATH);

							//加载了kerne32.dll以后，才能执行下面的下断点
							HMODULE hKernel = LoadLibraryA("kernel32.dll");
							dwHookApi = (DWORD)GetProcAddress(hKernel, szHookApi);
							bHookedApi = mgr.AddBp(dwHookApi, bpType, szHookApi);
						}

						break;
					}
					OutText(L"EXCEPTION_DEBUG_EVENT");

					DWORD dwAddr = 0;
					std::string name = "";
					if (mgr.isAtBps(dwAddr, name, false))
					{//到达硬件断点
						mgr.ClearBp(dwAddr, bpType);

						std::string strInfo = "到达断点:";
						strInfo += name.c_str();
						strInfo += " 是否DUMP?";
						std::wstring str = CA2CT(strInfo.c_str(), CP_ACP);

						if (dwAddr == dwHookApi)
						{//如果是到达的hook api断点, 读取用户代码地址
							CONTEXT context;
							context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
							BOOL bOk = ::GetThreadContext(m_pi.hThread, &context);
							assert(bOk);
							DWORD dwEspCODE;
							DWORD dwRead;
							ReadMemory(m_pi.hProcess, context.Esp, &dwEspCODE, 4, &dwRead);
							dwAddr = dwEspCODE;
						}
						if (MessageBox(m_hWnd, str.c_str(), TEXT("温馨提示"), MB_YESNO | MB_ICONQUESTION) == IDYES)
						{
							//dump
							DumpFunc(m_hWnd, m_pi.hProcess, m_pi.hThread, m_pi.dwProcessId, dwAddr - m_dwImageBase, 0);
						}
						break;
					}
					else
					{
						std::wstring str = format(L"ExceptionCode: %x ； ExceptionAddress: %p", debugEvent.u.Exception.ExceptionRecord.ExceptionCode, (DWORD)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
						OutText(str);

						if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT)
						{
							ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
							continue;
						}
					}
				}
				break;
				//other
				default:
				{
					std::wstring str = format(L"unknow event: %x", debugEvent.dwDebugEventCode);
					OutText(str);
					break;
				}
				}
				// Sleep(1000);
				//恢复线程
				ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
			}//WaitForDebugEvent ok
			else
			{
				//等待超时
				OutText(L"WaitForDebugEvent Failed");
				//结束进程
				//TerminateProcess(m_pi.hProcess, 0);
				break;
			}
		}//while
		OutText(L"Debug Process End");

		//关闭创建进程的句柄
		CloseHandle(m_pi.hProcess);
		CloseHandle(m_pi.hThread);
	}
	else
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
	}
}

//加载文件，创建进程  用于给力模式，或者插件模式, 或者侦壳模式，或者反汇编模式
//strFile=可执行程序名  strDllFile=要注入的插件名 bDetectShell=是否侦壳模式
void CreateProc(LPCTSTR strFile, LPCTSTR strDllFile, bool bDetectShell, bool bDisasmCode)
{
	if (lstrcmp(strFile, L"") == 0)
	{
		OutText(L"未选择文件");
		return;
	}

	// 定义启动参数
	// LPCTSTR applicationName = L"C:\\Path\\To\\YourApplication.exe"; // 替换为实际的可执行文件路径
	LPTSTR commandLine = nullptr; // 可以指定启动参数
	LPSECURITY_ATTRIBUTES processAttributes = nullptr;
	LPSECURITY_ATTRIBUTES threadAttributes = nullptr;
	BOOL inheritHandles = FALSE;
	DWORD creationFlags = CREATE_SUSPENDED; // 使用CREATE_SUSPENDED标志
	LPVOID environment = nullptr;
	LPCTSTR currentDirectory = nullptr; // 可以指定启动目录

	STARTUPINFO startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);

	// 启动新进程
	if (CreateProcess(
		strFile,
		commandLine,
		processAttributes,
		threadAttributes,
		inheritHandles,
		creationFlags,
		environment,
		currentDirectory,
		&startupInfo,
		&m_pi
	)) {

		HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
		pNtQueryInformationProcess NtQueryInformationProcess =
			(pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
		// 获取进程基本信息
		PROCESS_BASIC_INFORMATION pbi = { 0 };
		LONG status = NtQueryInformationProcess(
			m_pi.hProcess, 0, &pbi, sizeof(pbi), NULL
		);
		PVOID imageBaseAddress = NULL;
		ReadProcessMemory(m_pi.hProcess, (LPCVOID)((LPBYTE)pbi.PebBaseAddress + 0x08), &imageBaseAddress, sizeof(PVOID), NULL);

		m_dwImageBase = (DWORD)imageBaseAddress;  //修正imagebase(某些exe开启了动态基址时)

		if (m_hModPlugin && strDllFile)
		{//插件模式
			// 在目标进程中分配内存以存储DLL路径
			LPVOID remoteMemory = VirtualAllocEx(m_pi.hProcess, nullptr, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);

			// 将DLL路径写入目标进程的内存中
			WriteProcessMemory(m_pi.hProcess, remoteMemory, strDllFile, (wcslen(strDllFile) + 1) * sizeof(TCHAR), nullptr);

			// 在目标进程中创建一个远程线程来加载DLL
			HANDLE hThread = CreateRemoteThread(m_pi.hProcess, nullptr, 0,
				reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryW), remoteMemory, 0, nullptr);

		
			//调用插件的脱壳接口
			startUnpackFunc(m_pi, m_dwImageBase, m_dwImageBase + m_dwEpRva);

			if (hThread != nullptr)
			{
				// 等待远程线程完成
				WaitForSingleObject(hThread, INFINITE);

				// 关闭线程句柄
				CloseHandle(hThread);
			}
			else
			{
				OutText(L"Failed to create a remote thread.");
			}
		}
		else
		{//给力模式 或者侦壳模式(寻找OEP)，或者反汇编模式	
			if (bDisasmCode)
			{//反汇编模式	
				// 继续新进程的执行
				ResumeThread(m_pi.hThread);
				//等待进程启动完毕[如果是控制台程序，立即返回; 如果是GUI程序,等待其进入主界面],最多等待3秒钟
				WaitForInputIdle(m_pi.hProcess, 3000);
				//暂停进程执行
				SuspendThread(m_pi.hThread);
				return;
			}

			if (bDetectShell)
			{//侦壳模式(寻找OEP)
				// 继续新进程的执行
				ResumeThread(m_pi.hThread);
				//等待进程启动完毕[如果是控制台程序，立即返回; 如果是GUI程序,等待其进入主界面],最多等待3秒钟
				WaitForInputIdle(m_pi.hProcess, 3000);
				//暂停进程执行
				SuspendThread(m_pi.hThread);

				DWORD dwSizeOfFile = 0;
				HGLOBAL hMem = ReadProcess(m_hWnd, m_pi.hProcess, m_pi.dwProcessId, m_dwImageBase, dwSizeOfFile);
				if (hMem)                                   //如果返回的hMen不正确说明没有正确的申请到空间
				{
					IMAGE_DOS_HEADER* imDos_Headers = (IMAGE_DOS_HEADER *)hMem;	//设置初始指针地址
					if (imDos_Headers->e_magic == IMAGE_DOS_SIGNATURE)
					{
						IMAGE_NT_HEADERS* imNT_Headers = (IMAGE_NT_HEADERS *)((char *)hMem + imDos_Headers->e_lfanew);//NT头指针地址

						//开始侦壳
						//整个code段搜索
						for (int i = 0; i < g_shellCompile.size(); i++)
						{
							const char* pBaseCode = (const char*)hMem + imNT_Headers->OptionalHeader.BaseOfCode;
							DWORD dwSizeCode = imNT_Headers->OptionalHeader.SizeOfCode;

							int iFindOff = 0;
							if (DetectShell(pBaseCode, dwSizeCode, nullptr, g_shellCompile[i].signature, false, iFindOff))
							{//找到了
								std::wstring str = std::wstring(L"找到了:") + g_shellCompile[i].section;

								OutText(str);

								DWORD dwOEP = m_dwImageBase + imNT_Headers->OptionalHeader.BaseOfCode + iFindOff;
								std::wstring strOep = format(L"%08x", dwOEP);
								SetWindowText(GetDlgItem(m_hWnd, IDC_EDIT_OEP), strOep.c_str());
								break;
							}
						}
					}
					GlobalFree(hMem);                    //资源是可贵的，释放空间
				}
				//结束进程
				TerminateProcess(m_pi.hProcess, 0);
			}//侦壳模式
			else if (IsDlgButtonChecked(m_hWnd, IDC_CHECK_HOOKAPI))
			{//给力模式  HOOKAPI
				char szHookApi[MAX_PATH];
				GetDlgItemTextA(m_hWnd, IDC_CMB_HOOKAPI, szHookApi, MAX_PATH);

				// 在目标进程中分配内存以存储DLL路径
				LPVOID remoteMemory = VirtualAllocEx(m_pi.hProcess, nullptr, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);

				// 将DLL路径写入目标进程的内存中
				std::wstring szDllFile = L"kernel32.dll";
				WriteProcessMemory(m_pi.hProcess, remoteMemory, szDllFile.c_str(), (szDllFile.length() + 1) * sizeof(TCHAR), nullptr);

				// 在目标进程中创建一个远程线程来加载kernel32.DLL
				HANDLE hThread = CreateRemoteThread(m_pi.hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryW), remoteMemory, 0, nullptr);
				if (hThread != nullptr)
				{
					// 等待远程线程完成
					WaitForSingleObject(hThread, INFINITE);

					// 关闭线程句柄
					CloseHandle(hThread);
				}

				//加载了kerne32.dll以后，才能执行下面的下断点

				HMODULE hKernel = LoadLibraryA("kernel32.dll");
				DWORD dwAddr = (DWORD)GetProcAddress(hKernel, szHookApi);
				UpkMgr mgr(m_pi.dwProcessId, m_pi.dwThreadId);
				mgr.AddBp(dwAddr, UpkMgr::BT_SOFT, szHookApi);
				int iCount = 10;
				while (iCount--)
				{
					// 继续新进程的执行
					mgr.resume();
					::Sleep(1000);

					std::string strBpName = "";
					int iRet = mgr.isAtBps(dwAddr, strBpName, true);
					if (iRet == -1)
					{
						break;
					}
					else if (iRet == 1)
					{
						mgr.ClearBp(dwAddr, UpkMgr::BT_SOFT);
						CONTEXT ctx;
						mgr.RTU(ctx);

						std::string strInfo = "到达断点:";
						strInfo += strBpName.c_str();
						strInfo += " 是否DUMP?";
						std::wstring str = CA2CT(strInfo.c_str(), CP_ACP);

						if (MessageBox(m_hWnd, str.c_str(), TEXT("温馨提示"), MB_YESNO | MB_ICONQUESTION) == IDYES)
						{
							//dump
							DumpFunc(m_hWnd, m_pi.hProcess, m_pi.hThread, m_pi.dwProcessId, ctx.Eip - m_dwImageBase, 0);
							break;
						}
					}
				}
				TerminateThread(m_pi.hThread, 0);
			}
			else
			{
				// 继续新进程的执行
				ResumeThread(m_pi.hThread);
			}
			// 关闭句柄以避免资源泄漏
			CloseHandle(m_pi.hProcess);
			CloseHandle(m_pi.hThread);
		}//给力模式
	}
	else
	{
		OutText(L"Failed to start the new process.");
	}
}

//给力模式或者插件模式启动
void OnBnClickedBtnStart()
{
	TCHAR strFile[MAX_PATH];
	GetDlgItemText(m_hWnd, IDC_EDIT_FILENAME, strFile, MAX_PATH);
	TCHAR szPlugName[MAX_PATH];
	GetDlgItemText(m_hWnd, IDC_CM_PLUG, szPlugName, MAX_PATH);
	if (lstrcmp(szPlugName, L"给力模式") == 0)
	{
		//OutText(L"加载模块失败");
		///return;
	}
	else if (lstrcmp(szPlugName, L"调试模式") == 0)
	{
		//OutText(L"加载模块失败");
		DebugFile(strFile);
		return;
	}
	else
	{//插件模式
		if (!m_hModPlugin || m_strPluginPath.empty())
		{
			OutText(L"未加载插件");
			return;
		}
	}
	if (m_dwEpRva == 0)
	{
		OutText(L"不知道入口点");
		return;
	}
	CreateProc(strFile, m_strPluginPath.c_str(), false, false);
}

void EnumerateDllFiles(const std::wstring& directoryPath, std::vector<std::wstring>& dllFiles) {
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = FindFirstFile((directoryPath + L"\\*.dll").c_str(), &findFileData);

	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			dllFiles.push_back(findFileData.cFileName);
		} while (FindNextFile(hFind, &findFileData) != 0);

		FindClose(hFind);
	}
}


//插件信息
void OnBnClickedBtnInfo()
{
	if (!m_hModPlugin)
	{
		TCHAR szPlugName[MAX_PATH];
		GetDlgItemText(m_hWnd, IDC_CM_PLUG, szPlugName, MAX_PATH);
		if (lstrcmp(szPlugName, L"给力模式") == 0)
		{
			OutText(L"给力模式,测试中...");
			return;
		}
		else if (lstrcmp(szPlugName, L"调试模式") == 0)
		{
			OutText(L"Cool Debugger插件:Ver 0.1  (注意本调试器用来测试ANTI)");
			return;
		}

		std::wstring strDirPath = GetCurrentDir();
		strDirPath += L"\\plugin\\";
		strDirPath += szPlugName;
		m_hModPlugin = LoadLibrary(strDirPath.c_str());
	}

	if (!m_hModPlugin)
	{
		OutText(L"未加载插件");
		return;
	}
	else
	{
		// 2. 获取函数指针
		FARPROC pAboutPlugin = GetProcAddress(m_hModPlugin, "AboutPlugin");

		if (pAboutPlugin != nullptr) {
			// 3. 调用函数

			AboutPluginFunc aboutPluginFunc = reinterpret_cast<AboutPluginFunc>(pAboutPlugin);
			aboutPluginFunc(); // 调用AboutPlugin函数
		}
		else {
			OutText(L"Failed to get AboutPlugin pointer.");
		}
	}
}

void IsOepChecked()
{
	if (IsDlgButtonChecked(m_hWnd, IDC_CHECK_OEP))
	{//FINDOEP
		EnableWindow(GetDlgItem(m_hWnd, IDC_EDIT_OEP), TRUE);
		EnableWindow(GetDlgItem(m_hWnd, IDC_BTN_FINDOEP), TRUE);
		EnableWindow(GetDlgItem(m_hWnd, IDC_BTN_CODE), TRUE);
	}
	else
	{
		EnableWindow(GetDlgItem(m_hWnd, IDC_EDIT_OEP), FALSE);
		EnableWindow(GetDlgItem(m_hWnd, IDC_BTN_FINDOEP), FALSE);
		EnableWindow(GetDlgItem(m_hWnd, IDC_BTN_CODE), FALSE);
	}
	if (IsDlgButtonChecked(m_hWnd, IDC_CHECK_HOOKAPI))
	{//HOOKAPI
		EnableWindow(GetDlgItem(m_hWnd, IDC_CMB_HOOKAPI), TRUE);
	}
	else
	{//HOOKAPI
		EnableWindow(GetDlgItem(m_hWnd, IDC_CMB_HOOKAPI), FALSE);
	}
}

//反汇编对话框的消息处理程序
INT_PTR CALLBACK DisasmCodeWndProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		HWND hWindList = GetDlgItem(hDlg, IDC_LIST_DISASM);
		::SendMessage(hWindList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, (LPARAM)LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
		// 1. 初始化一个列结构体进行设置
		// 1.1 第一个字段 mask 表示想要应用哪些设置(对齐方式，文字，宽度)
		LVCOLUMN lvColumn = { LVCF_FMT | LVCF_TEXT | LVCF_WIDTH };
		// 1.2 设置对齐方式，第一列的对其方式始终是左对齐
		lvColumn.fmt = LVCFMT_LEFT;
		// 2.设置列名并添加列
		lvColumn.cx = 100;
		lvColumn.pszText = (LPWSTR)L"地址";
		ListView_InsertColumn(hWindList, 0, &lvColumn);

		lvColumn.cx = 150;
		lvColumn.pszText = (LPWSTR)L"代码";
		ListView_InsertColumn(hWindList, 1, &lvColumn);

		lvColumn.cx = 200;
		lvColumn.pszText = (LPWSTR)L"反汇编";
		ListView_InsertColumn(hWindList, 2, &lvColumn);

		CHAR strText[MAX_PATH];
		GetDlgItemTextA(m_hWnd, IDC_EDIT_OEP, strText, MAX_PATH);

		//创建进程
		TCHAR strFile[MAX_PATH];
		GetDlgItemText(m_hWnd, IDC_EDIT_FILENAME, strFile, MAX_PATH);
		CreateProc(strFile, L"", false, true);

		SetForegroundWindow(hDlg);

		g_dumpPara.hProcess = m_pi.hProcess;
		//反汇编代码
		char* str = nullptr;
		DWORD dwAddr = strtol(strText, &str, 16);
		DisasmCode(hWindList, dwAddr);

		//结束进程
		TerminateProcess(m_pi.hProcess, 0);
		// 关闭句柄以避免资源泄漏
		CloseHandle(m_pi.hProcess);
		CloseHandle(m_pi.hThread);

		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}


LRESULT OnSendString(WPARAM wParam, LPARAM lParam)
{
	if (wParam)
	{
		char* pStr = (char*)wParam;
		std::wstring str = CA2CT(pStr, CP_ACP);
		OutText(str);
	}
	return 0;
}

//恢复进程运行
LRESULT OnResume(WPARAM wParam, LPARAM lParam)
{
	// 继续新进程的执行
	ResumeThread(m_pi.hThread);

	// 等待新进程完成（如果需要）
	WaitForSingleObject(m_pi.hProcess, INFINITE);

	// 关闭句柄以避免资源泄漏
	CloseHandle(m_pi.hProcess);
	CloseHandle(m_pi.hThread);
	return 0;
}


//结束进程
LRESULT OnTerminate(WPARAM wParam, LPARAM lParam)
{
	//结束新进程的执行
	TerminateThread(m_pi.hThread, 0);
	TerminateProcess(m_pi.hProcess, 0);

	// 等待新进程完成（如果需要）
	//WaitForSingleObject(m_pi.hProcess, INFINITE);

	// 关闭句柄以避免资源泄漏
	//CloseHandle(m_pi.hProcess);
	//CloseHandle(m_pi.hThread);
	return 0;
}

LRESULT OnDumpNow(WPARAM wParam, LPARAM lParam)
{
	if (wParam)
	{
		DWORD dwOepVA = wParam;
		DWORD dwIatVA = lParam;
		std::wstring str = format(L"开始Dump OEP VA=%08x IAT VA=%08x", dwOepVA, dwIatVA);
		OutText(str);

		DumpFunc(m_hWnd, m_pi.hProcess, m_pi.hThread, m_pi.dwProcessId, dwOepVA - m_dwImageBase, dwIatVA - m_dwImageBase);

		//结束进程
		OnTerminate(0, 0);
	}
	return 0;
}

//获取一个进程的主线程ID
DWORD GetMainThreadId(HANDLE hProcess)
{
	LPVOID lpTid;

	_asm
	{
		mov eax, fs:[18h]
		add eax, 36
		mov[lpTid], eax
	}

	if (hProcess == NULL)
		return NULL;

	DWORD dwTid;
	if (ReadProcessMemory(hProcess, lpTid, &dwTid, sizeof(dwTid), NULL) == FALSE)
	{
		CloseHandle(hProcess);
		return NULL;
	}
	return dwTid;
}


BOOL CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (message)
	{
	case WM_CLOSE:
	{
		LRESULT lRes = DefWindowProc(hWnd, message, wParam, lParam);
		return lRes;
	}
	//EndDialog (hWnd, 0) ;
	return FALSE;

	case WM_DROPFILES:
	{
		// 处理拖拽消息
		HDROP hDrop = (HDROP)wParam;
		int nFiles = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0);
		TCHAR g_szDroppedFiles[MAX_PATH * 10] = { 0 };

		for (int i = 0; i < nFiles; ++i) {
			DragQueryFile(hDrop, i, g_szDroppedFiles, MAX_PATH);
			// 在这里可以处理拖拽的文件 g_szDroppedFiles
		}
		LoadFile(g_szDroppedFiles);

		// 清空保存文件列表的全局变量
		ZeroMemory(g_szDroppedFiles, sizeof(g_szDroppedFiles));
		DragFinish(hDrop);
	}
	return 0;

	case WM_INITDIALOG:
	{
		//获取调试权限
		setDebugPrivilege();
		m_hWnd = hWnd;
		HINSTANCE hInstance = (HINSTANCE)lParam;
		SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)LoadIcon(hInstance, MAKEINTRESOURCE(IDI_COOLDUMPPER)));
		m_hWindList = GetDlgItem(hWnd, IDC_LIST);

		// 设置输出窗口字体
		HWND hEdit = GetDlgItem(hWnd, IDC_EDIT_MSG);
		HFONT hFont = CreateFont(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"新宋体");
		SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0)); // 第二个参数为 TRUE 表示设置编辑框的字体

		::SendMessage(m_hWindList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, (LPARAM)LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
		InsertListViewColumns(m_hWindList);

		//枚举进程列表
		if (!GetProcessListFunc(hWnd, m_hWindList))
		{
			MessageBox(hWnd, TEXT("Fail to get the process"), TEXT("Sorry"), MB_OK | MB_ICONSTOP);
			//EndDialog(hWnd,0);			
		}

		HWND hCmOper = GetDlgItem(m_hWnd, IDC_CM_OPER);
		SendMessageW(hCmOper, CB_ADDSTRING, 0, (LPARAM)L"脱壳");
		SendMessageW(hCmOper, CB_SETCURSEL, 0, 0);

		std::wstring strDir = GetCurrentDir();
		//加载必要工具
		std::wstring strDisasm = strDir + L"\\tool\\Disasm.dll";
		m_hModDisam = LoadLibrary(strDisasm.c_str());
		if (!m_hModDisam)
			OutText(L"加载Disasm.dll失败");
		else
		{
			OutText(L"加载Disasm.dll成功");

			pDisasm = (pfnDisasm)GetProcAddress(m_hModDisam, "_Disasm@20");
			if (!pDisasm)
			{
				OutText(L"加载Disasm函数失败");
			}
		}

		std::wstring strUIF = strDir + L"\\tool\\UIF.dll";
		HMODULE hModUIF = LoadLibrary(strUIF.c_str());
		if (!hModUIF)
		{
			OutText(L"加载UIF.dll失败");
		}
		else
		{
			OutText(L"加载UIF.dll成功");
			UIF = (_UIF)GetProcAddress(hModUIF, "UIF");
		}

		//		std::wstring strImprec = strDir + L"\\tool\\ImpREC_DLL.dll";
		//		m_hModImprec = LoadLibrary(strImprec.c_str());
		//		if (!m_hModImprec)
		//		{
		//			OutText(L"加载ImpREC.dll失败");
		//		}
		//		else
		//		{
		//			OutText(L"加载ImpREC.dll成功");
		//
		//#if 0
		//			pRebuildImport = (pfnRebuildImport)GetProcAddress(m_hModImprec, "RebuildImport");
		//			if (!pRebuildImport)
		//			{
		//				OutText(L"加载RebuildImport函数失败");
		//			}
		//#else			
		//			pSetModule = (pfnSetModule)GetProcAddress(m_hModImprec, "SetModule");
		//			if (!pSetModule)
		//			{
		//				OutText(L"加载SetModule函数失败");
		//			}
		//			pLogIATEntry = (pfnLogIATEntry)GetProcAddress(m_hModImprec, "LogIATEntry");
		//			if (!pLogIATEntry)
		//			{
		//				OutText(L"加载LogIATEntry函数失败");
		//			}
		//			pMakeImportTable = (pfnMakeImportTable)GetProcAddress(m_hModImprec, "MakeImportTable");
		//			if (!pMakeImportTable)
		//			{
		//				OutText(L"加载MakeImportTable函数失败");
		//			}
		//#endif

		std::wstring strScylla = strDir + L"\\tool\\ScyllaDll.dll";
		HMODULE hModScylla = LoadLibrary(strScylla.c_str());
		if (!hModScylla)
		{
			OutText(L"加载ScyllaDll.dll失败");
		}
		else
		{
			OutText(L"加载ScyllaDll.dll成功");
			fixiat = (ScyllaIatFixAutoW)GetProcAddress(hModScylla, "ScyllaIatFixAutoW");
			if (!fixiat)
			{
				OutText(L"加载ScyllaIatFixAutoW函数失败");
			}

			HWND hCmbIat = GetDlgItem(m_hWnd, IDC_CM_IAT);
			SendMessageW(hCmbIat, CB_ADDSTRING, 0, (LPARAM)L"不处理");
			SendMessageW(hCmbIat, CB_ADDSTRING, 0, (LPARAM)L"ScyllaDll.dll");
			SendMessageW(hCmbIat, CB_ADDSTRING, 0, (LPARAM)L"插件修复");
			SendMessageW(hCmbIat, CB_SETCURSEL, 0, 0);
		}

		//枚举所有插件
		m_hModPlugin = nullptr;
		std::vector<std::wstring> dllFiles;

		EnumerateDllFiles(strDir + L"\\plugin", dllFiles);
		HWND hCmbPlug = GetDlgItem(m_hWnd, IDC_CM_PLUG);
		// 清空下拉列表控件中的所有项
		SendMessageW(hCmbPlug, CB_RESETCONTENT, 0, 0);
		SendMessageW(hCmbPlug, CB_ADDSTRING, 0, (LPARAM)L"给力模式");
		SendMessageW(hCmbPlug, CB_ADDSTRING, 0, (LPARAM)L"调试模式");
		for (auto strPlugName : dllFiles)
		{
			SendMessageW(hCmbPlug, CB_ADDSTRING, 0, (LPARAM)strPlugName.c_str());
		}
		// 设置默认插件选中项
		SendMessageW(hCmbPlug, CB_SETCURSEL, 0, 0);
		OnCbnSelchangeCmPlug();


		HWND hCmbHookApi = GetDlgItem(m_hWnd, IDC_CMB_HOOKAPI);
		SendMessage(hCmbHookApi, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0)); // 第二个参数为 TRUE 表示设置编辑框的字体

		SendMessageW(hCmbHookApi, CB_RESETCONTENT, 0, 0);
		SendMessageW(hCmbHookApi, CB_ADDSTRING, 0, (LPARAM)L"GetCommandLineA");
		SendMessageW(hCmbHookApi, CB_ADDSTRING, 0, (LPARAM)L"GetModuleHandleA");
		SendMessageW(hCmbHookApi, CB_ADDSTRING, 0, (LPARAM)L"GetStartupInfoA");
		SendMessageW(hCmbHookApi, CB_ADDSTRING, 0, (LPARAM)L"GetVersion");
		SendMessageW(hCmbHookApi, CB_ADDSTRING, 0, (LPARAM)L"GetVersionExA");
		// 设置默认选中项
		SendMessageW(hCmbHookApi, CB_SETCURSEL, 1, 0);
		CheckDlgButton(m_hWnd, IDC_CHECK_OEP, BST_CHECKED);
		SetWindowText(GetDlgItem(m_hWnd, IDC_EDIT_OEP), L"00401000");
		IsOepChecked();

		// 启用拖拽支持
		DragAcceptFiles(m_hWnd, TRUE);

		//读取壳特征码数据
		std::string szPath = GetCurrentDirA();
		szPath += "\\tool\\userdb.txt";
		if (ReadConfigFile(szPath, g_shellEp, g_shellEntry))
		{
			std::wstring strInfo = format(L"共加载%d条壳特征码", g_shellEp.size() + g_shellEntry.size());
			OutText(strInfo);
		}
		else {
			std::cerr << "Failed to read config file." << std::endl;
		}
		szPath = GetCurrentDirA();
		szPath += "\\tool\\userdb2.txt";
		if (ReadConfigFile(szPath, g_shellCompile, g_shellCompile))
		{
			std::wstring strInfo = format(L"共加载%d条编译器特征码", g_shellCompile.size());
			OutText(strInfo);
		}
		else {
			std::cerr << "Failed to read config file." << std::endl;
		}


		return TRUE;
	}
	case WM_CONTEXTMENU:
		if (wParam == (WPARAM)m_hWindList) {
			// 获取鼠标坐标
			POINT pt;
			GetCursorPos(&pt);

			HMENU hPopupMenu = CreatePopupMenu();
			AppendMenu(hPopupMenu, MF_STRING, IDM_DUMPNOW, L"Dump");
			AppendMenu(hPopupMenu, MF_STRING, IDM_CORSIZE, L"CorrectSize");

			AppendMenu(hPopupMenu, MF_STRING, IDM_REFRESH, L"Refresh");
			AppendMenu(hPopupMenu, MF_STRING, IDM_TERMINATE, L"Terminate");
			// 显示右键菜单
			TrackPopupMenu(hPopupMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
		}
		break;

	case WM_COMMAND:
	{
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// 分析菜单选择:
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, AboutWndProc);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		case IDM_REFRESH:
		{
			//枚举进程列表
			if (!GetProcessListFunc(hWnd, m_hWindList))
			{
				MessageBox(hWnd, TEXT("Fail to get the process"), TEXT("Sorry"), MB_OK | MB_ICONSTOP);
			}
			break;
		}
		case IDM_TERMINATE:
		{
			int selectedIndex = ListView_GetSelectionMark(m_hWindList);
			if (selectedIndex >= 0)
			{
				std::wstring sPID = L"";
				if (GetItemText(m_hWindList, selectedIndex, 0, sPID))
				{
					DWORD dwID = _wtol(sPID.c_str());
					HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, dwID);//使用上面获得的进程id
					if (!hProcess)
					{
						MessageBox(m_hWnd, TEXT("I can't open the process:("), TEXT("oh my god.."), MB_OK);
						return FALSE;
					}
					TerminateProcess(hProcess, 0);
					CloseHandle(hProcess);
				}
			}
			break;
		}
		case IDM_DUMPNOW:
		{
			int selectedIndex = ListView_GetSelectionMark(m_hWindList);
			if (selectedIndex >= 0)
			{
				std::wstring sPID = L"";
				std::wstring sPath = L"";

				if (GetItemText(m_hWindList, selectedIndex, 0, sPID) && GetItemText(m_hWindList, selectedIndex, 2, sPath))
				{
					GetFileEp(sPath, m_dwImageBase, m_dwCodeBase, m_dwEpRva);

					DWORD dwPID = _wtol(sPID.c_str());
					HANDLE hProcess = OpenProcess(PROCESS_VM_READ, 0, dwPID);//使用上面获得的进程id

					if (hProcess)
					{
						DWORD dwTid = GetMainThreadId(hProcess); //获取主线程ID
						if (dwTid)
						{
							HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, dwTid);
							DumpFunc(hWnd, hProcess, hThread, dwPID, m_dwEpRva, 0);
							CloseHandle(hProcess);   //有开始就，有关闭
						}
					}
				}
			}

			break;
		}
		case IDM_CORSIZE:
		{//修正映像大小
			int selectedIndex = ListView_GetSelectionMark(m_hWindList);
			if (selectedIndex >= 0)
			{
				std::wstring sPID = L"";
				if (GetItemText(m_hWindList, selectedIndex, 0, sPID))
				{
					DWORD dwID = _wtol(sPID.c_str());
					DWORD dwSizeOfImg = 0;
					if (CorrectSizeFunc(hWnd, m_hWindList, dwID, dwSizeOfImg))
					{
						//找到了以后，输出结果
						TCHAR szBuffer[100];
						TCHAR szMsg[] = L"原来的image size是：%08X\n修整的image size是：%08X";
						wsprintf(szBuffer, szMsg, GetSizeOfImage(hWnd, dwID, m_dwImageBase), dwSizeOfImg);
						MessageBox(hWnd, szBuffer, TEXT("纠正结果"), MB_OK);
					}
				}
			}
			break;
		}
		case IDC_BTN_LOAD:
		{
			//	SaveAsFunc(hWnd);
			OPENFILENAMEW ofn;
			TCHAR szFile[260];

			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hWnd;
			ofn.lpstrFile = szFile;
			ofn.lpstrFile[0] = '\0';
			ofn.nMaxFile = sizeof(szFile);
			ofn.lpstrFilter = L"可执行文件 (*.exe)\0*.exe\0动态链接库 (*.dll)\0*.dll\0所有文件(*.*)\0*.*\0\0";
			ofn.nFilterIndex = 1;
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = NULL;
			ofn.Flags = 0;

			if (GetOpenFileNameW(&ofn) == FALSE)
				return FALSE;

			std::wstring sFileName = ofn.lpstrFile;
			LoadFile(sFileName);

			break;
		}
		case IDC_BTN_CLEARLOG:
		{//清空日志
			ClearLog();
			break;
		}
		case IDC_BTN_INFO:
		{//插件信息
			OnBnClickedBtnInfo();
			break;
		}
		case IDC_BTN_START:
		{//开始脱壳
			OnBnClickedBtnStart();
			break;
		}
		case IDC_BTN_FINDOEP:
		{//寻找OEP
			TCHAR strFile[MAX_PATH];
			GetDlgItemText(m_hWnd, IDC_EDIT_FILENAME, strFile, MAX_PATH);
			CreateProc(strFile, L"", true, false);
			break;
		}
		case IDC_BTN_CODE:
		{//反汇编指定地址
			DialogBox(hInst, MAKEINTRESOURCE(IDD_DLG_DISASM), hWnd, DisasmCodeWndProc);
			break;
		}
		case IDC_CHECK_OEP:
		case IDC_CHECK_HOOKAPI:
		{
			IsOepChecked();

			break;
		}
		case IDC_CM_PLUG:
		{
			if (wmEvent == CBN_SELCHANGE)
				OnCbnSelchangeCmPlug();
			break;
		}
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	}
	case WM_SENDSTRING:
		OnSendString(wParam, lParam);
		break;
	case WM_TERMINATE:
		OnTerminate(wParam, lParam);
		break;
	case WM_DUMPNOW:
		OnDumpNow(wParam, lParam);
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		// TODO: 在此添加任意绘图代码...
		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	case WM_DEL_SECTION:
	{
		std::wstring str = format(L"设置移除区段数:%d", wParam);
		OutText(str);

		HWND hEdtDelSec = GetDlgItem(m_hWnd, IDC_EDT_DELSECTION);

		std::wstring strNum = format(L"%d", wParam);
		SendMessage(hEdtDelSec, WM_SETTEXT, 0, (LPARAM)strNum.c_str());
		break;
	}
	case WM_IMPFIX_MODE:
	{
		std::wstring str = format(L"设置输入表修复方式:%d", wParam);
		OutText(str);

		HWND comboBoxHandle = GetDlgItem(m_hWnd, IDC_CM_IAT);
		int selectedIndex = SendMessage(comboBoxHandle, CB_SETCURSEL, wParam, 0);
		break;
	}
	case WM_REBUILD_RES:
	{
		std::wstring str = format(L"设置重建资源");
		OutText(str);

		HWND hCheckbox = GetDlgItem(m_hWnd, IDC_CHECK_FIXRES);
		SendMessage(hCheckbox, BM_SETCHECK, BST_CHECKED, 0);

 
		break;
	}
	default:
		//return DefWindowProc(hWnd, message, wParam, lParam);
		break;
	}
	return FALSE;
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPTSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_COOLDUMPPER_DIALOG), NULL, MainWndProc, (LPARAM)hInstance);

	return TRUE;
}
