#pragma once

// ����TEB�ṹ���򻯰棬��������Ҫ��Ա��
typedef struct _TEB {
	PVOID Reserved1[12];        // Ԥ����Ա��32λ��64λռ�ÿռ䲻ͬ
	PVOID ProcessEnvironmentBlock;
} TEB, *PTEB;

// ����PEB�ṹ��������ImageBaseAddress��
typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;     // ģ�����ַ
} PEB, *PPEB;


// ����NtQueryInformationProcess����ԭ��
typedef LONG(WINAPI* pNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

// ����PROCESS_BASIC_INFORMATION�ṹ
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
