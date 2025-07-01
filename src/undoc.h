#pragma once

// 声明TEB结构（简化版，仅包含必要成员）
typedef struct _TEB {
	PVOID Reserved1[12];        // 预留成员，32位和64位占用空间不同
	PVOID ProcessEnvironmentBlock;
} TEB, *PTEB;

// 声明PEB结构（仅包含ImageBaseAddress）
typedef struct _PEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;     // 模块基地址
} PEB, *PPEB;


// 定义NtQueryInformationProcess函数原型
typedef LONG(WINAPI* pNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

// 定义PROCESS_BASIC_INFORMATION结构
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
