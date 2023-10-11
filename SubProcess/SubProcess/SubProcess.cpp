#include <stdio.h>
#include <windows.h>


int main()
{
	int i = 0;
	DWORD currentProcessId = GetCurrentProcessId();
	while (true) {
		i += 1;
		printf("############### 子进程id: %d, 第%d次等待 ####################\n", currentProcessId, i);
		Sleep(3000);
	}
}

