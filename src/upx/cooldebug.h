#include <Windows.h>
#include <tchar.h>
const long MAX_BUFFER = 256;

#pragma data_seg (".skylly")
HINSTANCE g_hDLL = NULL;		    //DLL ��instance
HWND  g_hWndList = NULL;			//�ѿǻ�����
TCHAR g_szNewMsg[256];				//��Ϣ����
TCHAR g_szBackCode[256];			//���뱸��
TCHAR g_szAboutMe[MAX_BUFFER] = "UPX���:";
TCHAR g_szVersion[MAX_BUFFER] = "Ver 0.2 ";
TCHAR g_szStartUnpack[MAX_BUFFER] = "Start Unpacking...";
TCHAR g_szInitOk[MAX_BUFFER] = "��ʼ�����!";
TCHAR g_szError[MAX_BUFFER] = "��ѡ�����˰�!";
TCHAR g_szOK[MAX_BUFFER] = "���������!";
#pragma data_seg ()

#include "../plugin.h"