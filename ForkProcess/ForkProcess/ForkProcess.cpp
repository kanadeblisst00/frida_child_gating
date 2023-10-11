#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <Shlwapi.h>


int main() {
	// 定义进程信息结构体
	PROCESS_INFORMATION pi;
	// 定义启动信息结构体
	STARTUPINFO si;
	// 初始化结构体
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// 获取当前可执行文件的路径
	wchar_t exePath[MAX_PATH];
	GetModuleFileName(NULL, exePath, MAX_PATH);

	// 从路径中提取目录部分
	wchar_t exeDir[MAX_PATH];
	wcscpy_s(exeDir, exePath);
	PathRemoveFileSpecW(exeDir);

	// 要运行的可执行文件的名称
	LPCWSTR applicationName = L"SubProcess.exe"; // 替换为你要运行的可执行文件的名称

	// 创建完整的可执行文件路径
	wchar_t fullPath[MAX_PATH];
	swprintf(fullPath, MAX_PATH, L"%s\\%s", exeDir, applicationName);

	// 文件路径作为命令行参数
	LPWSTR cmdLine = NULL;

	DWORD currentProcessId = GetCurrentProcessId();

	// 创建新进程
	if (CreateProcessW(fullPath, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		printf("新进程已成功创建！\n");
		printf("新进程的进程ID：%d, 当前进程id: %d \n", pi.dwProcessId, currentProcessId);

		// 可以等待进程结束，或者继续执行其他操作
		// WaitForSingleObject(pi.hProcess, INFINITE);

		// 关闭进程和线程句柄
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else {
		printf("无法创建新进程。错误代码：%d", GetLastError());
	}
	int i = 0;
	
	while (true) {
		i += 1;
		printf("*************** 父进程id: %d, 第%d次等待 *******************\n", currentProcessId, i);
		Sleep(2000);
	}

	return 0;
}
