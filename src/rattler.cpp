##include "stdafx.h"
#include <windows.h>
#include <psapi.h>
#include <string>
#include <algorithm>
#include "resource.h"
#include <tlhelp32.h>
#include "Shlobj.h"

using namespace::std;

std::string globalChecker = "";

std::wstring wStringDLLs[200];
std::wstring test2DLLsToTest[200];
std::wstring testThreeDLLsToTest[200];

std::wstring test1VulnearbleDLLs[100];
std::wstring test2VulnearbleDLLs[100];
std::wstring test3VulnearbleDLLs[100];

int test1TargetCount = 0;
int test2TargetCount = 0;
int test3TargetCount = 0;

int test1VulnCount = 0;
int test2VulnCount = 0;
int test3VulnCount = 0;

TCHAR * targetAppPath;

DWORD GetParentProcessID(DWORD dwProcessID)
{
	DWORD dwParentProcessID = -1;
	HANDLE			hProcessSnapshot;
	PROCESSENTRY32	processEntry32;

	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot != INVALID_HANDLE_VALUE)
	{
		processEntry32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hProcessSnapshot, &processEntry32))
		{
			do
			{
				if (dwProcessID == processEntry32.th32ProcessID)
				{
					dwParentProcessID = processEntry32.th32ParentProcessID;
					break;
				}
			} while (Process32Next(hProcessSnapshot, &processEntry32));
			CloseHandle(hProcessSnapshot);
		}
	}
	return dwParentProcessID;
}


int killProcessWithProcessID(DWORD processID)
{
	//cout << "\nDEBUG: ATTEMPTING TO KILL: " << processID;
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	if (!TerminateProcess(processHandle, 0))
	{
		//cout << "ERROR: CANT KILL PROCESS: " << processID << ", ERROR CODE-> " << GetLastError() << endl;
		return 0;
	}
	else
	{
		WaitForSingleObject(processHandle, INFINITE);
		// Close process and thread handles. 
		CloseHandle(processHandle);
		return 0;
	}
}



DWORD FindProcessId(const std::wstring& processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}


int killProcess(const std::wstring& processName)
{
	int processIdToKill = FindProcessId(processName);
	killProcessWithProcessID(processIdToKill);
	return 0;
}



void PrintProcessNameAndID(DWORD currentProcess, DWORD targetParentProcessID)
{

	DWORD currentProcessParentProcessID = GetParentProcessID(currentProcess);
	if (currentProcessParentProcessID == targetParentProcessID&&currentProcess !=targetParentProcessID)
	{
		killProcessWithProcessID(currentProcess);
	}
}

int KillChildrenProcesses(DWORD parentProcessID)
{
	//cout << "\nDEBUG: GETTING CHILDREN FOR: " << parentProcessID << endl;
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		cout << "\nERROR: GETTING SYSTEM PROCESSES, ERROR CODE: " << GetLastError() << endl;
		return 1;
	}
	else
	{
		// Calculate how many process identifiers were returned.
		cProcesses = cbNeeded / sizeof(DWORD);

		// Print the name and process identifier for each process.
		for (i = 0; i < cProcesses; i++)
		{
			if (aProcesses[i] != 0)
			{
				PrintProcessNameAndID(aProcesses[i], parentProcessID);
			}
		}
		return 0;
	}
}



int checkPayload(int numTest,wstring currentTargetDLL)
{
	if (FindProcessId(L"Calculator.exe")| FindProcessId(L"calc.exe"))
	{
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hStdout == INVALID_HANDLE_VALUE)
		{
			cout << "[-] ERROR: Error while getting input handle" << endl;
			return EXIT_FAILURE;
		}
		//sets the color to intense red on blue background
		SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		
		 if (numTest==2)
		{
			wcout << "\n[*] INFO: DLL IS VULNERABLE TO EXECUTABLE TEST-> " << currentTargetDLL << endl;
			test2VulnearbleDLLs[test2VulnCount] = currentTargetDLL;
			test2VulnCount++;
		}
		else if (numTest == 3)
		{
			wcout << "\n[*] INFO: DLL IS VULNERABLE TO DOWNLOADS INSTALLER TEST-> " << currentTargetDLL << endl;
			test3VulnearbleDLLs[test3VulnCount] = currentTargetDLL;
			test3VulnCount++;
		}
		//reverting back to the normal color
		SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		return 0;
	}
	else
	{
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hStdout == INVALID_HANDLE_VALUE)
		{
			cout << "[-] ERROR: Error while getting input handle" << endl;
			return EXIT_FAILURE;
		}
		//sets the color to intense red on blue background
		SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);

		if (numTest==2)
		{
			cout << "\n[*] TARGET DLL IS NOT VULNERABLE TO EXECUTABLE TEST "<< endl;
		}
		else if (numTest==3)
		{
			cout << "\n[*] TARGET DLL IS NOT VULNERABLE TO DOWNLOADS INSTALLER TEST " << endl;
		}
		//reverting back to the normal color
		SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		return 0;
	}
}


int PrintModules(DWORD processID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;
	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (NULL == hProcess)
	{
		cout << "[-] ERROR: COULD NOT GET HANDLE ON PROCESS: " << processID << "\n";
		return 1;
	}

	TCHAR targetProcessPath[MAX_PATH];

	GetModuleFileNameEx(hProcess, NULL, targetProcessPath, sizeof(targetProcessPath) / sizeof(TCHAR));
 
	// Get a list of all the modules in this process.
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR dllFullPath[MAX_PATH];

			if (GetModuleFileNameEx(hProcess, hMods[i], dllFullPath, sizeof(dllFullPath) / sizeof(TCHAR)))
			{
				
				wstring wstringDllFullPath(dllFullPath);
				string stringDllFullPath(wstringDllFullPath.begin(), wstringDllFullPath.end());
				std::transform(stringDllFullPath.begin(), stringDllFullPath.end(), stringDllFullPath.begin(), ::tolower);
				std::size_t found = stringDllFullPath.find(".dll");

				std::size_t foundLastBackSlash = stringDllFullPath.find_last_of("\\");
				string dllPath = stringDllFullPath.substr(0,foundLastBackSlash+1);
				std::wstring wstrTargetProcessPath = (targetProcessPath);
				string strTargetProcessPath(wstrTargetProcessPath.begin(), wstrTargetProcessPath.end());
				std::transform(strTargetProcessPath.begin(), strTargetProcessPath.end(), strTargetProcessPath.begin(), ::tolower);

				foundLastBackSlash = strTargetProcessPath.find_last_of("\\");
				string exePath = strTargetProcessPath.substr(0,foundLastBackSlash+1);
				
				if (found != std::string::npos)
				{
					testThreeDLLsToTest[test3TargetCount] = wstringDllFullPath;
					test3TargetCount++;

					if (dllPath.compare(exePath))
					{
						test2DLLsToTest[test2TargetCount] = wstringDllFullPath;
						test2TargetCount++;
					}
				}
			}
		}
	}
	// Release the handle to the process.
	CloseHandle(hProcess);
	return 0;
}


int copyFile(TCHAR *fileToCopy, TCHAR *copiedFileName)
{
	if (CopyFile(fileToCopy, copiedFileName, FALSE))
	{
		return 0;
	}
	else
	{
		cout << "ERROR: FAILED COPYING, WINDOWS ERROR CODE-> " <<GetLastError() <<endl;
		return 1;
	}
}


int startUp(TCHAR *targetAppPath)
{
	printf("[+] STARTING UP...\n");
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess(targetAppPath,   // No module name (use command line)
		NULL,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("[-] ERROR: CreateProcess failed (%d).\n", GetLastError());
		system("pause");
		return 0;
	}
	else
	{
		DWORD procID = pi.dwProcessId;
		printf("[*] TARGET PROCESS ID: %d\n", procID);
		Sleep(9000);
		PrintModules(procID);
		KillChildrenProcesses(procID);
		killProcessWithProcessID(procID);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}
}


int doDllFoo(wstring targetDLL)
{
	wstring postfix = (L"_ORIG");

	wstring fileToCopyWSTRING(targetDLL);
	TCHAR * fileToCopyTCHAR = (wchar_t *)fileToCopyWSTRING.c_str();

	wstring copiedFileNameWSTRING = (targetDLL);
	copiedFileNameWSTRING = copiedFileNameWSTRING + postfix;

	TCHAR * copiedFileNameTCHAR = (wchar_t *)copiedFileNameWSTRING.c_str();

	copyFile(fileToCopyTCHAR, copiedFileNameTCHAR);

	copyFile(L"payload.dll", fileToCopyTCHAR);

	return 0;
}

int prepTest2(wstring targetExecutablePath, wstring dllToTest)
{
	string str(targetExecutablePath.begin(), targetExecutablePath.end());
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);

	std::size_t found = str.find_last_of("\\");

	string workingDirectory= str.substr(0, found + 1);

	string strDllName(dllToTest.begin(), dllToTest.end());
	std::transform(strDllName.begin(), strDllName.end(), strDllName.begin(), ::tolower);

	std::size_t findDll = strDllName.find_last_of("\\");

	string strJustDllFileName = strDllName.substr(findDll + 1);

	std::wstring wsTmp(workingDirectory.begin(), workingDirectory.end());

	std::wstring dllFileName(strJustDllFileName.begin(), strJustDllFileName.end());

	wstring fileToCopyWSTRING = wsTmp+dllFileName;
	
	TCHAR * fileToCopyTCHAR = (wchar_t *)fileToCopyWSTRING.c_str();

	copyFile(L"payload.dll", fileToCopyTCHAR);

	return 0;
}

int test2(wstring targetDLL)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess(targetAppPath,   // No module name (use command line)
		NULL,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("[-] ERROR: CREATE PROCESS FAILED (%d).\n", GetLastError());
		checkPayload(2,targetDLL);
		return 0;
	}
	else
	{
		DWORD procID = pi.dwProcessId;
		Sleep(2000);
		checkPayload(2,targetDLL);
		KillChildrenProcesses(pi.dwProcessId);
		TerminateProcess(pi.hProcess, 0);
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}
}

int cleanUpTest2(wstring targetExecutablePath, wstring dllToTest)
{
	string str(targetExecutablePath.begin(), targetExecutablePath.end());
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);

	std::size_t found = str.find_last_of("\\");

	string workingDirectory = str.substr(0, found + 1);

	string strDllName(dllToTest.begin(), dllToTest.end());
	std::transform(strDllName.begin(), strDllName.end(), strDllName.begin(), ::tolower);

	std::size_t findDll = strDllName.find_last_of("\\");

	string strDllName2(dllToTest.begin(), dllToTest.end());

	string strJustDllFileName = strDllName2.substr(findDll + 1);
	std::wstring dllFileName(strJustDllFileName.begin(), strJustDllFileName.end());

	std::wstring wsTmp(workingDirectory.begin(), workingDirectory.end());
	wstring fileToDeleteWSTRING = wsTmp + dllFileName;
	TCHAR * fileToDeleteTCHAR = (wchar_t *)fileToDeleteWSTRING.c_str();

	if (!DeleteFile(fileToDeleteTCHAR))
	{
		wcout << "\n[-] ERROR:EXECUTABLE TEST COULD NOT DELETE FILE: " << fileToDeleteTCHAR << ", ERROR CODE: " << GetLastError() << endl;;
	}

	killProcess(L"Calculator.exe");

	return 0;
}

int printStats(int numTest)
{
	HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdout == INVALID_HANDLE_VALUE)
	{
		cout << "[-] ERROR: Error while getting input handle" << endl;
		return EXIT_FAILURE;
	}
	SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_INTENSITY);

	if (numTest==2)
	{
		cout << "\n[+] EXECUTABLE TEST TOTAL DLL's IDENTIFIED: " << test2TargetCount;
		cout << "\n[+] EXECUTABLE TEST TOTAL VULN COUNT: " << test2VulnCount;

		for (int loop2 = 0; loop2 < test2VulnCount; loop2++)
		{
			wcout << "\n[*] EXECUTABLE TEST VULNERABLE DLL-> " << test2VulnearbleDLLs[loop2];
		}
	}
	else if (numTest==3)
	{
		cout << "\n[+] DOWNLOAD INSTALLER TEST TOTAL DLL's IDENTIFIED: " << test3TargetCount;
		cout << "\n[+] DOWNLOAD INSTALLER TEST TOTAL VULN COUNT: " << test3VulnCount;

		for (int loop3 = 0; loop3 < test3VulnCount; loop3++)
		{
			wcout << "\n[*] DOWNLOAD INSTALLER TEST VULNERABLE DLL-> " << test3VulnearbleDLLs[loop3];
		}
	}
	
	SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	cout << endl;
}


int implementTest2(wstring targetAppPath)
{
	for (int count = 0; count < test2TargetCount; count++)
	{
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hStdout == INVALID_HANDLE_VALUE)
		{
			cout << "[-] ERROR: Error while getting input handle" << endl;
			return EXIT_FAILURE;
		}
		SetConsoleTextAttribute(hStdout, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE);
		wcout << "\n[*] TARGETING DLL-> " << test2DLLsToTest[count];
		SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		prepTest2(targetAppPath, test2DLLsToTest[count]);
		test2(test2DLLsToTest[count]);
		cleanUpTest2(targetAppPath, test2DLLsToTest[count]);
		SetConsoleTextAttribute(hStdout, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE);
		//wcout << "\n[*] FINISHED EXECUTABLE TEST\n";
		SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
	return 0;
}

int prepTest3(wstring dllToTest)
{
	PWSTR path;
	SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &path);
	std::wstring wsPath(path);
	string strDllName(dllToTest.begin(), dllToTest.end());
	std::transform(strDllName.begin(), strDllName.end(), strDllName.begin(), ::tolower);
	std::size_t findDll = strDllName.find_last_of("\\");
	string strJustDllFileName = strDllName.substr(findDll + 1);
	std::wstring dllFileName(strJustDllFileName.begin(), strJustDllFileName.end());
	wstring middle = L"\\";
	wstring finalPath = path + middle + dllFileName;
	TCHAR * fileToCopyTCHAR = (wchar_t *)finalPath.c_str();
	copyFile(L"payload.dll", fileToCopyTCHAR);
	return 0;
}

int test3(wstring targetDLL)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess(targetAppPath,   // No module name (use command line)
		NULL,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("[-] ERROR: CREATE PROCESS FAILED (%d).\n", GetLastError());
		checkPayload(3, targetDLL);
		return 0;
	}
	else
	{
		DWORD procID = pi.dwProcessId;
		Sleep(2000);
		checkPayload(3, targetDLL);
		KillChildrenProcesses(pi.dwProcessId);
		TerminateProcess(pi.hProcess, 0);
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}
}

int cleanUpTest3(wstring dllToTest)
{
	PWSTR path;
	SHGetKnownFolderPath(FOLDERID_Downloads, 0, NULL, &path);
	std::wstring wsPath(path);
	string strDllName(dllToTest.begin(), dllToTest.end());
	std::transform(strDllName.begin(), strDllName.end(), strDllName.begin(), ::tolower);

	std::size_t findDll = strDllName.find_last_of("\\");

	string strJustDllFileName = strDllName.substr(findDll + 1);
	std::wstring dllFileName(strJustDllFileName.begin(), strJustDllFileName.end());

	wstring middle = L"\\";
	wstring finalPath = path + middle + dllFileName;
	//wcout << "\nFINAL COPY PATH: " << finalPath << endl;

	TCHAR * fileToDeleteTCHAR = (wchar_t *)finalPath.c_str();


	if (!DeleteFile(fileToDeleteTCHAR))
	{
		wcout << "\n[-] ERROR:DOWNLOAD INSTALLER TEST COULD NOT DELETE FILE: " << fileToDeleteTCHAR <<", ERROR CODE: "<<GetLastError()<< endl;;
	}

	killProcess(L"Calculator.exe");
	return 0;
}

int implementTest3()
{
	for (int count = 0; count < test3TargetCount; count++)
	{
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hStdout == INVALID_HANDLE_VALUE)
		{
			cout << "[-] ERROR: Error while getting input handle" << endl;
			return EXIT_FAILURE;
		}
		SetConsoleTextAttribute(hStdout, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE);

		wcout << "\n[*] TARGETING DLL-> " << testThreeDLLsToTest[count];

		SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

		prepTest3(testThreeDLLsToTest[count]);
		test3(testThreeDLLsToTest[count]);
		cleanUpTest3(test2DLLsToTest[count]);

		SetConsoleTextAttribute(hStdout, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_BLUE);
		SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
	return 0;
}

int main(int argc, char *argv[], char *envp)
{
	printf("[+] RATTLER \n");

	if (argc < 3)
	{
		printf("[*] USAGE: Rattler.exe \"c:\\Path\\To\\Target\\Executable.exe\" 1\2 \n");
		system("pause");
		return 0;
	}
	else
	{
		printf("[*] TARGET APPLICATION: %s\n", argv[1]);

		size_t newsize = strlen(argv[1]) + 1;
		wchar_t * wcstring = new wchar_t[newsize];
		size_t convertedChars = 0;
		mbstowcs_s(&convertedChars, wcstring, newsize, argv[1], _TRUNCATE);
		globalChecker = "vlc";				
		targetAppPath = wcstring;
		startUp(targetAppPath);

		if (strcmp(argv[2], "1") == 0)
		{
			printf("[+] IMPLEMENTING EXECUTABLE TEST");
			implementTest2(targetAppPath);
			printStats(2);
			system("pause");
		}
		else if (strcmp(argv[2], "2") == 0)
		{
			printf("[+] IMPLEMENTING INSTALLER DOWNLOADS TEST");
			implementTest3();
			printStats(3);
			system("pause");
		}
		else
		{
			printf("[-] ERROR, I don't know what to do :\\..");
		}
	}
}
