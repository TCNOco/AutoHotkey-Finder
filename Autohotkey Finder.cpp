#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Advapi32.lib")
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
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

struct ProcessInfo {
    std::wstring name;
    DWORD pid;
    std::wstring reason;
};

std::atomic<bool> scanning{ true };
std::wstring currentProcess;
std::mutex currentProcessMutex;
std::mutex resultMutex;
std::vector<ProcessInfo> flaggedProcesses;
std::vector<ProcessInfo> unscannableProcesses;

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

bool terminateProcess(DWORD pid, const std::wstring& name) {
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

int wmain() {
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
        std::wcout << L"Press 'y' to continue scanning, 'a' to always continue, any other key to exit: ";
        wchar_t ch = _getwch();
        std::wcout << ch << L"\n"; // Echo the character for user feedback
        if (ch == L'a' || ch == L'A') {
            setAlwaysContinue();
            std::wcout << L"'Always continue' preference saved. Future runs will skip this prompt.\n";
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
        std::wcout << L"Press Enter to exit...";
        std::wcin.get();
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

    std::wstring input;
    std::getline(std::wcin, input);

    if (input.empty()) {
        std::wcout << L"No selection made. Exiting...\n";
        return 0;
    }

    try {
        int choice = std::stoi(input);
        if (choice == 0) {
            std::wcout << L"\nAttempting to kill all AutoHotkey processes...\n";
            int killed = 0;
            for (const auto& proc : flaggedProcesses) {
                if (terminateProcess(proc.pid, proc.name)) {
                    killed++;
                }
            }
            std::wcout << L"\nSummary: " << killed << L" out of " << flaggedProcesses.size() << L" processes terminated.\n";
        }
        else if (choice >= 1 && choice <= static_cast<int>(flaggedProcesses.size())) {
            const auto& proc = flaggedProcesses[choice - 1];
            std::wcout << L"\nAttempting to kill " << proc.name << L" (PID " << proc.pid << L")...\n";
            terminateProcess(proc.pid, proc.name);
        }
        else {
            std::wcout << L"Invalid choice. Exiting...\n";
        }
    }
    catch (...) {
        std::wcout << L"Invalid input. Exiting...\n";
    }

    std::wcout << L"Press Enter to exit...";
    std::wcin.get();
    return 0;
}
