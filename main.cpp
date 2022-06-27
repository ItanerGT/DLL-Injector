#include <iostream>
#include <Windows.h>
using namespace std;

int InjectDLL(DWORD, char*);
int getDLLpath(char*);
int getPID(int*);
int getProc(HANDLE*, DWORD);

int getDLLpath(char* dll) {
	std::cout << "Please enter the path to DLL file\n";
	std::cin >> dll;
	return 1;
}

int getPID(int* PID) {
	std::cout << "Please enter the PID to your target process\n";
	std::cin >> *PID;
	return 1;
}

int getProc(HANDLE* handleToProc, DWORD PID) {
	*handleToProc = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
	DWORD dwLastError = GetLastError();
	if (*handleToProc == NULL) {
		std::cout << "Unable to open process\n";
		return -1;
	}
	else {
		std::cout << "Process opened\n";
		return 1;
	}
}

int InjectDLL(DWORD PID, char* dll) {
	HANDLE handleToProc;
	LPVOID LoadLibAddr;
	LPVOID baseAddr;
	HANDLE remThread;

	// Get dll length
	int dllLength = strlen(dll) + 1;

	// We get the processing of the process
	if (getProc(&handleToProc, PID) < 0) {
		return -1;
	}

	// Download kernel32.dll
	LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibrayA");

	if (!LoadLibAddr) {
		return -1;
	}

	baseAddr = VirtualAllocEx(handleToProc, NULL, dllLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!baseAddr) {
		return -1;
	}

	// Write the path to the dll
	if (!WriteProcessMemory(handleToProc, baseAddr, dll, dllLength, NULL)) {
		return -1;
	}

	// Creating a remote thread
	remThread = CreateRemoteThread(handleToProc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, baseAddr, 0, NULL);

	if (!remThread) {
		return -1;
	}

	WaitForSingleObject(remThread, INFINITE);

	VirtualFreeEx(handleToProc, baseAddr, dllLength, MEM_RELEASE);

	// Closing a handler
	if (CloseHandle(remThread) == 0) {
		std::cout << "Failed to close handle to remote thread\n";
		return -1;
	}

	if (CloseHandle(handleToProc) == 0) {
		std::cout << "Failed to close handle to target process\n";
		return -1;
	}
}

int main() {
	SetConsoleTitle("DLL-Injector");

	int PID = -1;
	char* dll = new char[255];

	getDLLpath(dll);
	getPID(&PID);
	InjectDLL(PID, dll);
	system("pause");

	return 0;
}