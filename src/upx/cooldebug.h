#include <Windows.h>
#include <tchar.h>
const long MAX_BUFFER = 256;

#pragma data_seg (".skylly")
HINSTANCE g_hDLL = NULL;		    //DLL 的instance
HWND  g_hWndList = NULL;			//脱壳机窗口
TCHAR g_szNewMsg[256];				//消息缓存
TCHAR g_szBackCode[256];			//代码备份
TCHAR g_szAboutMe[MAX_BUFFER] = "UPX插件:";
TCHAR g_szVersion[MAX_BUFFER] = "Ver 0.2 ";
TCHAR g_szStartUnpack[MAX_BUFFER] = "Start Unpacking...";
TCHAR g_szInitOk[MAX_BUFFER] = "初始化完毕!";
TCHAR g_szError[MAX_BUFFER] = "你选错插件了吧!";
TCHAR g_szOK[MAX_BUFFER] = "你是最棒的!";
#pragma data_seg ()

#include "../plugin.h"