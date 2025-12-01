#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <propkey.h>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cwctype>
#include <fstream>
#include <thread>
#include <future>
#include <atomic>
#include <mutex>
#include <set>
#include <map>
#include <conio.h>
#include <limits>

// This program scans running processes on the system to detect AutoHotkey executables.
// It does not scan process memory; it examines file version info and binaries on disk.
// Prompt: Press 'y' to continue scanning, 'a' to always continue (saved to registry), any other key exits.
WORD g_defaultConsoleAttributes = 0;

void initDefaultConsoleColor() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        g_defaultConsoleAttributes = csbi.wAttributes;
    }
}

void setConsoleColor(WORD attributes) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, attributes);
}

class Spinner {
public:
    static constexpr const char* frames = "|/-\\";
    int index = 0;
    char next() {
        char c = frames[index++];
        index %= 4;
        return c;
    }
};

void clearConsoleLine()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) return;

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;

    COORD cursorPos = csbi.dwCursorPosition;
    cursorPos.X = 0;

    DWORD charsWritten = 0;
    DWORD width = csbi.dwSize.X;

    FillConsoleOutputCharacterW(hConsole, L' ', width, cursorPos, &charsWritten);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, width, cursorPos, &charsWritten);

    SetConsoleCursorPosition(hConsole, cursorPos);
}

void flushInputBuffer() {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) return;
    
    // Flush the console input buffer
    FlushConsoleInputBuffer(hStdin);
    
    // Clear any buffered input from cin
    std::wcin.clear();
    // Discard any remaining characters in the input buffer
    if (std::wcin.rdbuf()->in_avail() > 0) {
        std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), L'\n');
    }
}

struct ProcessInfo {
    std::wstring name;
    DWORD pid;
    std::wstring reason;
};

struct TerminatedProcess {
    std::wstring name;
    std::wstring path;
    std::wstring arguments;
    std::wstring workingDir;
};

std::atomic<bool> scanning{ true };
std::wstring currentProcess;
std::mutex currentProcessMutex;
std::mutex resultMutex;
std::vector<ProcessInfo> flaggedProcesses;
std::vector<ProcessInfo> unscannableProcesses;

// List of executable names that should be terminated if found
static const std::vector<std::wstring> terminationList = {
    L"Flow.Launcher.exe"
};

// Registry path for persisting the "always continue" user preference
static const wchar_t* REG_PATH = L"Software\\tc.ht\\AHKFinder";

bool isAlwaysContinue() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;
    DWORD val = 0, type = 0, size = sizeof(val);
    LONG res = RegQueryValueExW(hKey, L"AlwaysContinue", nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size);
    RegCloseKey(hKey);
    return (res == ERROR_SUCCESS && type == REG_DWORD && val == 1);
}

void setAlwaysContinue() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
        DWORD val = 1;
        RegSetValueExW(hKey, L"AlwaysContinue", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));
        RegCloseKey(hKey);
    }
}

bool shortcutExists() {
    wchar_t desktopPath[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, SHGFP_TYPE_CURRENT, desktopPath) != S_OK) {
        return false;
    }

    wchar_t shortcutPath[MAX_PATH];
    wcscpy_s(shortcutPath, desktopPath);
    wcscat_s(shortcutPath, L"\\AHK Finder.lnk");

    DWORD dwAttrib = GetFileAttributesW(shortcutPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool createDesktopShortcut() {
    // Define SLDF_RUNAS_USER if not already defined (for older SDKs)
    #ifndef SLDF_RUNAS_USER
    #define SLDF_RUNAS_USER 0x2000
    #endif

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to initialize COM: " << hr << L"\n";
        return false;
    }

    IShellLinkW* pShellLink = nullptr;
    hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pShellLink));
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create ShellLink instance: " << hr << L"\n";
        CoUninitialize();
        return false;
    }

    // Get PowerShell path
    wchar_t powershellPath[MAX_PATH];
    DWORD pathSize = MAX_PATH;
    if (SHGetFolderPathW(nullptr, CSIDL_SYSTEM, nullptr, SHGFP_TYPE_CURRENT, powershellPath) != S_OK) {
        pShellLink->Release();
        CoUninitialize();
        std::wcerr << L"Failed to get system folder path\n";
        return false;
    }
    wcscat_s(powershellPath, L"\\WindowsPowerShell\\v1.0\\powershell.exe");

    // Set the target path to PowerShell
    pShellLink->SetPath(powershellPath);
    
    // Set the arguments to run the command
    pShellLink->SetArguments(L"-NoProfile -ExecutionPolicy Bypass -Command \"iex (irm ahk.tc.ht)\"");
    
    // Set the working directory
    wchar_t workingDir[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, SHGFP_TYPE_CURRENT, workingDir) == S_OK) {
        pShellLink->SetWorkingDirectory(workingDir);
    }

    // Set the description
    pShellLink->SetDescription(L"TroubleChute Autohotkey Finder");

    // Set the shortcut to run as administrator
    IShellLinkDataList* pShellLinkDataList = nullptr;
    hr = pShellLink->QueryInterface(IID_PPV_ARGS(&pShellLinkDataList));
    if (SUCCEEDED(hr)) {
        DWORD dwFlags = 0;
        hr = pShellLinkDataList->GetFlags(&dwFlags);
        if (SUCCEEDED(hr)) {
            dwFlags |= SLDF_RUNAS_USER;
            hr = pShellLinkDataList->SetFlags(dwFlags);
        }
        pShellLinkDataList->Release();
    }

    // Get the IPersistFile interface to save the shortcut
    IPersistFile* pPersistFile = nullptr;
    hr = pShellLink->QueryInterface(IID_PPV_ARGS(&pPersistFile));
    if (FAILED(hr)) {
        pShellLink->Release();
        CoUninitialize();
        std::wcerr << L"Failed to get IPersistFile interface: " << hr << L"\n";
        return false;
    }

    // Get desktop path
    wchar_t desktopPath[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, SHGFP_TYPE_CURRENT, desktopPath) != S_OK) {
        pPersistFile->Release();
        pShellLink->Release();
        CoUninitialize();
        std::wcerr << L"Failed to get desktop folder path\n";
        return false;
    }

    // Create the shortcut file path
    wchar_t shortcutPath[MAX_PATH];
    wcscpy_s(shortcutPath, desktopPath);
    wcscat_s(shortcutPath, L"\\AHK Finder.lnk");

    // Save the shortcut
    hr = pPersistFile->Save(shortcutPath, TRUE);
    pPersistFile->Release();
    pShellLink->Release();
    CoUninitialize();

    if (FAILED(hr)) {
        std::wcerr << L"Failed to save shortcut: " << hr << L"\n";
        return false;
    }

    return true;
}

bool restartProcesses(const std::vector<TerminatedProcess>& processes) {
    int restarted = 0;
    for (const auto& proc : processes) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };
        
        std::wstring cmdLine = L"\"";
        cmdLine += proc.path;
        cmdLine += L"\"";
        if (!proc.arguments.empty()) {
            cmdLine += L" ";
            cmdLine += proc.arguments;
        }

        std::vector<wchar_t> cmdLineBuf(cmdLine.begin(), cmdLine.end());
        cmdLineBuf.push_back(L'\0');

        std::wstring workingDir = proc.workingDir;
        if (workingDir.empty() && !proc.path.empty()) {
            size_t lastSlash = proc.path.find_last_of(L"\\/");
            if (lastSlash != std::wstring::npos) {
                workingDir = proc.path.substr(0, lastSlash + 1);
            }
        }

        if (CreateProcessW(
            proc.path.c_str(),
            cmdLineBuf.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            workingDir.empty() ? nullptr : workingDir.c_str(),
            &si,
            &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            std::wcout << L"Restarted: " << proc.name << L"\n";
            restarted++;
        } else {
            std::wcout << L"Failed to restart: " << proc.name << L" (Error: " << GetLastError() << L")\n";
        }
    }
    return restarted > 0;
}

bool createRelaunchShortcut(const std::vector<TerminatedProcess>& processes) {
    if (processes.empty()) {
        return false;
    }

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::wcerr << L"Failed to initialize COM: " << hr << L"\n";
        return false;
    }

    IShellLinkW* pShellLink = nullptr;
    hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pShellLink));
    if (FAILED(hr)) {
        std::wcerr << L"Failed to create ShellLink instance: " << hr << L"\n";
        CoUninitialize();
        return false;
    }

    // Get PowerShell path
    wchar_t powershellPath[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_SYSTEM, nullptr, SHGFP_TYPE_CURRENT, powershellPath) != S_OK) {
        pShellLink->Release();
        CoUninitialize();
        std::wcerr << L"Failed to get system folder path\n";
        return false;
    }
    wcscat_s(powershellPath, L"\\WindowsPowerShell\\v1.0\\powershell.exe");

    // Build PowerShell command to restart all processes
    std::wstring psCommand = L"-NoProfile -ExecutionPolicy Bypass -Command \"";
    for (size_t i = 0; i < processes.size(); ++i) {
        const auto& proc = processes[i];
        if (i > 0) psCommand += L"; ";
        psCommand += L"Start-Process -FilePath '";
        psCommand += proc.path;
        psCommand += L"'";
        if (!proc.arguments.empty()) {
            psCommand += L" -ArgumentList '";
            // Escape single quotes in arguments
            std::wstring escapedArgs = proc.arguments;
            size_t pos = 0;
            while ((pos = escapedArgs.find(L"'", pos)) != std::wstring::npos) {
                escapedArgs.replace(pos, 1, L"''");
                pos += 2;
            }
            psCommand += escapedArgs;
            psCommand += L"'";
        }
        if (!proc.workingDir.empty()) {
            psCommand += L" -WorkingDirectory '";
            psCommand += proc.workingDir;
            psCommand += L"'";
        }
    }
    psCommand += L"\"";

    // Set the target path to PowerShell
    pShellLink->SetPath(powershellPath);
    pShellLink->SetArguments(psCommand.c_str());
    
    // Set the working directory
    wchar_t workingDir[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, SHGFP_TYPE_CURRENT, workingDir) == S_OK) {
        pShellLink->SetWorkingDirectory(workingDir);
    }

    // Set the description
    pShellLink->SetDescription(L"Relaunch Programs - Autohotkey Finder");

    // Get the IPersistFile interface to save the shortcut
    IPersistFile* pPersistFile = nullptr;
    hr = pShellLink->QueryInterface(IID_PPV_ARGS(&pPersistFile));
    if (FAILED(hr)) {
        pShellLink->Release();
        CoUninitialize();
        std::wcerr << L"Failed to get IPersistFile interface: " << hr << L"\n";
        return false;
    }

    // Get desktop path
    wchar_t desktopPath[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, SHGFP_TYPE_CURRENT, desktopPath) != S_OK) {
        pPersistFile->Release();
        pShellLink->Release();
        CoUninitialize();
        std::wcerr << L"Failed to get desktop folder path\n";
        return false;
    }

    // Create the shortcut file path
    wchar_t shortcutPath[MAX_PATH];
    wcscpy_s(shortcutPath, desktopPath);
    wcscat_s(shortcutPath, L"\\Relaunch Programs (AHK Finder).lnk");

    // Save the shortcut (overwrite if exists)
    hr = pPersistFile->Save(shortcutPath, TRUE);
    pPersistFile->Release();
    pShellLink->Release();
    CoUninitialize();

    if (FAILED(hr)) {
        std::wcerr << L"Failed to save shortcut: " << hr << L"\n";
        return false;
    }

    return true;
}

bool containsIgnoreCase(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        size_t j = 0;
        for (; j < needle.size(); ++j) {
            if (towlower(haystack[i + j]) != towlower(needle[j])) break;
        }
        if (j == needle.size()) return true;
    }
    return false;
}

bool isInTerminationList(const std::wstring& processName) {
    for (const auto& exeName : terminationList) {
        if (containsIgnoreCase(processName, exeName)) {
            return true;
        }
    }
    return false;
}

bool loadFile(const std::wstring& path, std::vector<BYTE>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize sz = f.tellg();
    if (sz <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize((size_t)sz);
    return (bool)f.read(reinterpret_cast<char*>(out.data()), sz);
}

bool binaryContainsAHK(const std::vector<BYTE>& data) {
    static const std::string marker = "AutoHotkey";
    size_t n = data.size(), m = marker.size();
    if (n < m) return false;
    for (size_t i = 0; i + m <= n; ++i) {
        size_t j = 0;
        for (; j < m; ++j) {
            if (tolower(data[i + j]) != tolower(marker[j])) break;
        }
        if (j == m) return true;
    }
    return false;
}

bool GetVersionStringValue(const std::wstring& filePath,
    const std::wstring& key,
    std::wstring& outValue)
{
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
    if (size == 0) return false;

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(filePath.c_str(), handle, size, data.data()))
        return false;

    struct LANGANDCODEPAGE { WORD wLanguage, wCodePage; } *trans = nullptr;
    UINT transBytes = 0;
    if (!VerQueryValueW(data.data(),
        L"\\VarFileInfo\\Translation",
        reinterpret_cast<void**>(&trans), &transBytes) ||
        transBytes < sizeof(*trans))
    {
        return false;
    }

    wchar_t subBlock[100];
    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s",
        trans->wLanguage, trans->wCodePage, key.c_str());

    LPVOID valuePtr = nullptr;
    UINT valueLen = 0;
    if (!VerQueryValueW(data.data(), subBlock, &valuePtr, &valueLen) || valueLen == 0)
        return false;

    outValue.assign(static_cast<wchar_t*>(valuePtr), valueLen);
    return true;
}

// NtQueryInformationProcess structures and constants
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef NTSTATUS (WINAPI *PNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
);

#define ProcessCommandLineInformation 60

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

bool getProcessCommandLine(DWORD pid, std::wstring& outCmdLine) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return false;
    }

    // Load NtDll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        CloseHandle(hProcess);
        return false;
    }

    PNtQueryInformationProcess NtQueryInformationProcess = 
        (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        CloseHandle(hProcess);
        return false;
    }

    // Get PEB address
    PROCESS_BASIC_INFORMATION pbi = {0};
    DWORD returnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    if (status != 0 || !pbi.PebBaseAddress) {
        CloseHandle(hProcess);
        return false;
    }

    // Read PEB
    PVOID pebAddress = pbi.PebBaseAddress;
    PVOID processParameters = nullptr;
    SIZE_T bytesRead = 0;
    
    // Read ProcessParameters pointer from PEB (offset 0x20 on x64, 0x10 on x86)
#ifdef _WIN64
    if (!ReadProcessMemory(hProcess, (PBYTE)pebAddress + 0x20, &processParameters, sizeof(PVOID), &bytesRead)) {
        CloseHandle(hProcess);
        return false;
    }
#else
    if (!ReadProcessMemory(hProcess, (PBYTE)pebAddress + 0x10, &processParameters, sizeof(PVOID), &bytesRead)) {
        CloseHandle(hProcess);
        return false;
    }
#endif

    if (!processParameters) {
        CloseHandle(hProcess);
        return false;
    }

    // Read CommandLine UNICODE_STRING (offset 0x70 on x64, 0x40 on x86)
    UNICODE_STRING cmdLine = {0};
#ifdef _WIN64
    if (!ReadProcessMemory(hProcess, (PBYTE)processParameters + 0x70, &cmdLine, sizeof(UNICODE_STRING), &bytesRead)) {
        CloseHandle(hProcess);
        return false;
    }
#else
    if (!ReadProcessMemory(hProcess, (PBYTE)processParameters + 0x40, &cmdLine, sizeof(UNICODE_STRING), &bytesRead)) {
        CloseHandle(hProcess);
        return false;
    }
#endif

    if (!cmdLine.Buffer || cmdLine.Length == 0) {
        CloseHandle(hProcess);
        return false;
    }

    // Read the command line string
    std::vector<wchar_t> buffer(cmdLine.Length / sizeof(wchar_t) + 1);
    if (!ReadProcessMemory(hProcess, cmdLine.Buffer, buffer.data(), cmdLine.Length, &bytesRead)) {
        CloseHandle(hProcess);
        return false;
    }

    buffer[cmdLine.Length / sizeof(wchar_t)] = L'\0';
    outCmdLine = buffer.data();
    CloseHandle(hProcess);
    return true;
}

bool getProcessInfo(DWORD pid, const std::wstring& name, TerminatedProcess& outInfo) {
    outInfo.name = name;
    outInfo.path.clear();
    outInfo.arguments.clear();
    outInfo.workingDir.clear();

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        return false;
    }

    // Get process path first (fallback)
    wchar_t buf[MAX_PATH];
    DWORD len = _countof(buf);
    std::wstring fallbackPath;
    if (QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
        fallbackPath = buf;
        outInfo.path = fallbackPath;
        // Extract working directory from path as fallback
        size_t lastSlash = fallbackPath.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            outInfo.workingDir = fallbackPath.substr(0, lastSlash + 1);
        }
    }

    // Get command line (this is more accurate)
    std::wstring cmdLine;
    if (getProcessCommandLine(pid, cmdLine)) {
        // Parse command line to separate path and arguments
        if (!cmdLine.empty()) {
            // Remove quotes if present
            if (cmdLine[0] == L'"') {
                size_t endQuote = cmdLine.find(L'"', 1);
                if (endQuote != std::wstring::npos) {
                    outInfo.path = cmdLine.substr(1, endQuote - 1);
                    if (endQuote + 1 < cmdLine.length() && cmdLine[endQuote + 1] == L' ') {
                        outInfo.arguments = cmdLine.substr(endQuote + 2);
                    }
                } else {
                    outInfo.path = cmdLine;
                }
            } else {
                // No quotes, find first space
                size_t firstSpace = cmdLine.find(L' ');
                if (firstSpace != std::wstring::npos) {
                    outInfo.path = cmdLine.substr(0, firstSpace);
                    outInfo.arguments = cmdLine.substr(firstSpace + 1);
                } else {
                    outInfo.path = cmdLine;
                }
            }
            // Update working directory from new path if we got it from command line
            if (!outInfo.path.empty()) {
                size_t lastSlash = outInfo.path.find_last_of(L"\\/");
                if (lastSlash != std::wstring::npos) {
                    outInfo.workingDir = outInfo.path.substr(0, lastSlash + 1);
                }
            }
        }
    }

    CloseHandle(hProc);
    return !outInfo.path.empty();
}

bool terminateProcess(DWORD pid, const std::wstring& name, std::vector<TerminatedProcess>& terminatedList) {
    // Get process info before terminating
    TerminatedProcess procInfo;
    if (getProcessInfo(pid, name, procInfo)) {
        terminatedList.push_back(procInfo);
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        std::wcout << L"Failed to open process " << name << L" (PID " << pid << L") for termination.\n";
        return false;
    }

    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);

    if (result) {
        std::wcout << L"Successfully terminated " << name << L" (PID " << pid << L")\n";
        return true;
    }
    else {
        std::wcout << L"Failed to terminate " << name << L" (PID " << pid << L")\n";
        return false;
    }
}

void scanProcess(const PROCESSENTRY32W& pe, DWORD selfPid) {
    DWORD pid = pe.th32ProcessID;
    if (pid == selfPid) {
        return;
    }
    std::wstring name = pe.szExeFile;

    {
        std::lock_guard<std::mutex> lk(currentProcessMutex);
        currentProcess = name;
    }

    // Check if process is in termination list
    if (isInTerminationList(name)) {
        std::lock_guard<std::mutex> lk(resultMutex);
        flaggedProcesses.push_back({ name, pid, L"In termination list" });
        return;
    }

    if (containsIgnoreCase(name, L"autohotkey.exe") ||
        containsIgnoreCase(name, L"autohotkeyu64.exe"))
    {
        std::lock_guard<std::mutex> lk(resultMutex);
        flaggedProcesses.push_back({ name, pid, L"Native AutoHotkey executable" });
        return;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::lock_guard<std::mutex> lk(resultMutex);
        unscannableProcesses.push_back({ name, pid, L"Cannot open process" });
        return;
    }

    wchar_t buf[MAX_PATH];
    DWORD len = _countof(buf);
    if (!QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
        CloseHandle(hProc);
        std::lock_guard<std::mutex> lk(resultMutex);
        unscannableProcesses.push_back({ name, pid, L"Path query failed" });
        return;
    }
    std::wstring path = buf;
    CloseHandle(hProc);

    std::wstring comp, desc;
    if ((GetVersionStringValue(path, L"CompanyName", comp) &&
        containsIgnoreCase(comp, L"autohotkey")) ||
        (GetVersionStringValue(path, L"FileDescription", desc) &&
            containsIgnoreCase(desc, L"autohotkey")))
    {
        std::lock_guard<std::mutex> lk(resultMutex);
        flaggedProcesses.push_back({ name, pid, L"Version info contains AutoHotkey" });
        return;
    }

    std::vector<BYTE> data;
    if (loadFile(path, data) && binaryContainsAHK(data)) {
        std::lock_guard<std::mutex> lk(resultMutex);
        flaggedProcesses.push_back({ name, pid, L"Binary scan detected AutoHotkey" });
    }
}

int wmain(int argc, wchar_t* argv[]) {
    // Check for "s" option to create desktop shortcut
    if (argc > 1 && (wcscmp(argv[1], L"s") == 0 || wcscmp(argv[1], L"-s") == 0 || wcscmp(argv[1], L"/s") == 0)) {
        initDefaultConsoleColor();
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"Creating desktop shortcut...\n";
        setConsoleColor(g_defaultConsoleAttributes);
        
        if (createDesktopShortcut()) {
            setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            std::wcout << L"Desktop shortcut created successfully!\n";
            setConsoleColor(g_defaultConsoleAttributes);
            std::wcout << L"Press Enter to exit...";
            std::wcin.get();
            return 0;
        } else {
            setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::wcout << L"Failed to create desktop shortcut.\n";
            setConsoleColor(g_defaultConsoleAttributes);
            std::wcout << L"Press Enter to exit...";
            std::wcin.get();
            return 1;
        }
    }

    initDefaultConsoleColor();
    setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"Welcome to the TroubleChute AHK Finder.\n";
    setConsoleColor(g_defaultConsoleAttributes);
    std::wcout << L"This script is provided AS-IS without warranty of any kind. See https://tc.ht/privacy & https://tc.ht/terms.\n";
    std::wcout << L"Find the source code at https://github.com/TCNOco/AutoHotkey-Finder\n\n";

    setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"This program scans running processes on the system to detect AutoHotkey executables.\n";
    std::wcout << L"It does not scan process memory; it examines file version info and binaries on disk.\n\n";
    std::wcout << L"While it should not trigger anticheats, please make sure all games with anticheats are closed before continuing!\n\n";
    setConsoleColor(g_defaultConsoleAttributes);
    if (!isAlwaysContinue()) {
        flushInputBuffer();
        std::wcout << L"Press 'y' to continue scanning, 'a' to always continue, 's' to create a Desktop Shortcut, any other key to exit: ";
        wchar_t ch = _getwch();
        std::wcout << ch << L"\n"; // Echo the character for user feedback
        if (ch == L'a' || ch == L'A') {
            setAlwaysContinue();
            std::wcout << L"'Always continue' preference saved. Future runs will skip this prompt.\n";
        } else if (ch == L's' || ch == L'S') {
            std::wcout << L"\nCreating desktop shortcut...\n";
            if (createDesktopShortcut()) {
                setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::wcout << L"Desktop shortcut created successfully!\n";
                setConsoleColor(g_defaultConsoleAttributes);
                std::wcout << L"Press Enter to exit...";
                std::wcin.get();
            } else {
                setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::wcout << L"Failed to create desktop shortcut.\n";
                setConsoleColor(g_defaultConsoleAttributes);
                std::wcout << L"Press Enter to exit...";
                std::wcin.get();
            }
            return 0;
        } else if (ch != L'y' && ch != L'Y') {
            return 0;
        }
    } else {
        std::wcout << L"Auto-continue enabled (registry). Starting scan...\n";
    }

    Spinner spinner;
    DWORD selfPid = GetCurrentProcessId();

    std::thread spinThread([&]() {
        while (scanning) {
            char frame = spinner.next();
            std::wstring nameCopy;
            {
                std::lock_guard<std::mutex> lk(currentProcessMutex);
                nameCopy = currentProcess;
            }
            clearConsoleLine();
            std::wcout << L"Scanning processes... " << frame << L" " << nameCopy;
            std::wcout.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        clearConsoleLine();
        std::wcout << L"Scanning processes... done.\n";
        });

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        scanning = false;
        spinThread.join();
        std::cerr << "Error: could not snapshot processes.\n";
        return 1;
    }

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        scanning = false;
        spinThread.join();
        std::cerr << "Error: failed to enumerate processes.\n";
        return 1;
    }

    std::vector<PROCESSENTRY32W> processes;
    do {
        processes.push_back(pe);
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);

    std::vector<std::future<void>> futures;
    futures.reserve(processes.size());
    for (auto& p : processes) {
        futures.emplace_back(std::async(std::launch::async, scanProcess, p, selfPid));
    }
    for (auto& f : futures) {
        f.get();
    }

    scanning = false;
    spinThread.join();

    // Clear any keypresses that occurred during scanning
    flushInputBuffer();

    std::wcout << L"\n";

    if (!unscannableProcesses.empty()) {
        std::wcout << L"Processes that could not be scanned: ";
        bool first = true;
        for (const auto& proc : unscannableProcesses) {
            if (!first) std::wcout << L", ";
            std::wcout << proc.name << L" (PID " << proc.pid << L")";
            first = false;
        }
        std::wcout << L"\n\n\n";
        setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"Please run this program as Administrator to better search programs\n\n";
        setConsoleColor(g_defaultConsoleAttributes);
    }

    if (flaggedProcesses.empty()) {
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"No AutoHotkey processes detected.\n";
        setConsoleColor(g_defaultConsoleAttributes);
        
        // If always continue is enabled and shortcut doesn't exist, prompt for shortcut
        if (isAlwaysContinue() && !shortcutExists()) {
            flushInputBuffer();
            std::wcout << L"\nDo you want a desktop shortcut to this app? 'Y' for yes, any other key to exit: ";
            wchar_t ch = _getwch();
            std::wcout << ch << L"\n";
            if (ch == L'y' || ch == L'Y') {
                std::wcout << L"\nCreating desktop shortcut...\n";
                if (createDesktopShortcut()) {
                    setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::wcout << L"Desktop shortcut created successfully!\n";
                    setConsoleColor(g_defaultConsoleAttributes);
                } else {
                    setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::wcout << L"Failed to create desktop shortcut.\n";
                    setConsoleColor(g_defaultConsoleAttributes);
                }
                std::wcout << L"Press Enter to exit...";
                std::wcin.get();
            }
        } else {
            std::wcout << L"Press Enter to exit...";
            std::wcin.get();
        }
        return 0;
    }

    setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::wcout << L"AutoHotkey processes detected:\n";
    for (size_t i = 0; i < flaggedProcesses.size(); ++i) {
        const auto& proc = flaggedProcesses[i];
        std::wcout << L" " << (i + 1) << L". " << proc.name << L" (PID " << proc.pid << L") [" << proc.reason << L"]\n";
    }
    setConsoleColor(g_defaultConsoleAttributes);

    std::wcout << L"\nOptions:\n";
    std::wcout << L" 0. Kill all AutoHotkey processes\n";
    std::wcout << L" 1-" << flaggedProcesses.size() << L". Kill specific process\n";
    std::wcout << L" Any other key: Exit without killing\n";
    setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"\nEnter your choice: ";
    setConsoleColor(g_defaultConsoleAttributes);

    flushInputBuffer();
    std::wstring input;
    std::getline(std::wcin, input);

    if (input.empty()) {
        std::wcout << L"No selection made. Exiting...\n";
        return 0;
    }

    std::vector<TerminatedProcess> terminatedProcesses;
    
    try {
        int choice = std::stoi(input);
        if (choice == 0) {
            std::wcout << L"\nAttempting to kill all AutoHotkey processes...\n";
            int killed = 0;
            for (const auto& proc : flaggedProcesses) {
                if (terminateProcess(proc.pid, proc.name, terminatedProcesses)) {
                    killed++;
                }
            }
            std::wcout << L"\nSummary: " << killed << L" out of " << flaggedProcesses.size() << L" processes terminated.\n";
        }
        else if (choice >= 1 && choice <= static_cast<int>(flaggedProcesses.size())) {
            const auto& proc = flaggedProcesses[choice - 1];
            std::wcout << L"\nAttempting to kill " << proc.name << L" (PID " << proc.pid << L")...\n";
            terminateProcess(proc.pid, proc.name, terminatedProcesses);
        }
        else {
            std::wcout << L"Invalid choice. Exiting...\n";
            return 0;
        }
    }
    catch (...) {
        std::wcout << L"Invalid input. Exiting...\n";
        return 0;
    }

    // Show terminated processes with their launch arguments
    if (!terminatedProcesses.empty()) {
        std::wcout << L"\n";
        setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::wcout << L"Terminated processes with launch arguments:\n";
        setConsoleColor(g_defaultConsoleAttributes);
        for (size_t i = 0; i < terminatedProcesses.size(); ++i) {
            const auto& proc = terminatedProcesses[i];
            std::wcout << L" " << (i + 1) << L". " << proc.name << L"\n";
            std::wcout << L"    Path: " << proc.path << L"\n";
            if (!proc.arguments.empty()) {
                std::wcout << L"    Arguments: " << proc.arguments << L"\n";
            }
            if (!proc.workingDir.empty()) {
                std::wcout << L"    Working Directory: " << proc.workingDir << L"\n";
            }
        }
        std::wcout << L"\n";
        std::wcout << L"----------------\n";
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"AutoHotKey is now closed. You can play games requiring it to be closed.\n\n";
        setConsoleColor(g_defaultConsoleAttributes);
        std::wcout << L"When done, you can restart them by pressing 'r', or hit 's' to create a desktop shortcut to relaunch them later. Otherwise press any other key to exit\n\n";
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"Options:\n";
        std::wcout << L"  r - Restart all terminated processes\n";
        std::wcout << L"  s - Create/Update 'Relaunch Programs' shortcut\n";
        std::wcout << L"  c - Create shortcut to the AHK Finder program\n";
        std::wcout << L"  Any other key - Exit\n";
        std::wcout << L"\nEnter your choice: ";
        setConsoleColor(g_defaultConsoleAttributes);
        
        flushInputBuffer();
        wchar_t ch = _getwch();
        std::wcout << ch << L"\n";
        
        if (ch == L'r' || ch == L'R') {
            std::wcout << L"\nRestarting processes...\n";
            restartProcesses(terminatedProcesses);
            std::wcout << L"\nPress Enter to exit...";
            std::wcin.get();
        }
        else if (ch == L's' || ch == L'S') {
            std::wcout << L"\nCreating/updating 'Relaunch Programs' shortcut...\n";
            if (createRelaunchShortcut(terminatedProcesses)) {
                setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::wcout << L"Shortcut created/updated successfully!\n";
                setConsoleColor(g_defaultConsoleAttributes);
            } else {
                setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::wcout << L"Failed to create shortcut.\n";
                setConsoleColor(g_defaultConsoleAttributes);
            }
            std::wcout << L"Press Enter to exit...";
            std::wcin.get();
        }
        else if (ch == L'c' || ch == L'C') {
            std::wcout << L"\nCreating desktop shortcut to AHK Finder...\n";
            if (createDesktopShortcut()) {
                setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                std::wcout << L"Desktop shortcut created successfully!\n";
                setConsoleColor(g_defaultConsoleAttributes);
            } else {
                setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                std::wcout << L"Failed to create desktop shortcut.\n";
                setConsoleColor(g_defaultConsoleAttributes);
            }
            std::wcout << L"Press Enter to exit...";
            std::wcin.get();
        }
        else {
            std::wcout << L"Exiting...\n";
        }
    } else {
        // If always continue is enabled and shortcut doesn't exist, prompt for shortcut
        if (isAlwaysContinue() && !shortcutExists()) {
            flushInputBuffer();
            std::wcout << L"\nDo you want a desktop shortcut to this app? 'Y' for yes, any other key to exit: ";
            wchar_t ch = _getwch();
            std::wcout << ch << L"\n";
            if (ch == L'y' || ch == L'Y') {
                std::wcout << L"\nCreating desktop shortcut...\n";
                if (createDesktopShortcut()) {
                    setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::wcout << L"Desktop shortcut created successfully!\n";
                    setConsoleColor(g_defaultConsoleAttributes);
                } else {
                    setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::wcout << L"Failed to create desktop shortcut.\n";
                    setConsoleColor(g_defaultConsoleAttributes);
                }
                std::wcout << L"Press Enter to exit...";
                std::wcin.get();
            }
        } else {
            std::wcout << L"Press Enter to exit...";
            std::wcin.get();
        }
    }
    
    return 0;
}
