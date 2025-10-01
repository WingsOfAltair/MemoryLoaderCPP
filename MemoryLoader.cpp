// Read x64dbg exported byte patch list (second arg) and apply patches to a launched process (first arg).
// Usage: loader.exe "C:\path\to\target.exe" "C:\path\to\patches.txt"

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <cstdint>
#include <fstream>
#include <map>
#include <algorithm>

struct Sequence {
    uint64_t startAddr;
    std::vector<uint8_t> orig;
    std::vector<uint8_t> repl;
};

// Constants
const DWORD PROCESS_ALL_ACCESS_CUSTOM = (0x000F0000 | 0x00100000 | 0xFFF);
const DWORD PAGE_EXECUTE_READ_ = 0x20;
const DWORD PAGE_EXECUTE_READWRITE_ = 0x40;
const DWORD PAGE_EXECUTE_WRITECOPY_ = 0x80;
const DWORD EXECUTABLE_PROTECTIONS = PAGE_EXECUTE_READ_ | PAGE_EXECUTE_READWRITE_ | PAGE_EXECUTE_WRITECOPY_;

// ----------------- utility -----------------
static inline bool hexByteToUint8(const std::string& hex, uint8_t& out) {
    unsigned int v = 0;
    std::stringstream ss;
    ss << std::hex << hex;
    if (!(ss >> v)) return false;
    out = static_cast<uint8_t>(v & 0xFF);
    return true;
}

// Parse x64dbg export file. returns true on success, fills 'moduleName' (if present) and 'sequences'
bool parseX64dbgExport(const std::string& path, std::string& moduleName, std::vector<Sequence>& sequences) {
    std::ifstream ifs(path);
    if (!ifs) {
        std::cerr << "Failed to open file: " << path << "\n";
        return false;
    }

    std::map<uint64_t, std::pair<uint8_t, uint8_t>> entries; // addr -> (orig, repl)
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        if (line[0] == '>') {
            moduleName = line.substr(1);
            // trim whitespace
            size_t s = moduleName.find_first_not_of(" \t\r\n");
            size_t e = moduleName.find_last_not_of(" \t\r\n");
            if (s != std::string::npos && e != std::string::npos)
                moduleName = moduleName.substr(s, e - s + 1);
            continue;
        }

        size_t colon = line.find(':');
        size_t arrow = line.find("->");
        if (colon == std::string::npos || arrow == std::string::npos) continue;

        std::string addrStr = line.substr(0, colon);
        std::string origHex = line.substr(colon + 1, arrow - (colon + 1));
        std::string replHex = line.substr(arrow + 2);

        auto trim = [](std::string& s) {
            size_t a = s.find_first_not_of(" \t\r\n");
            size_t b = s.find_last_not_of(" \t\r\n");
            if (a == std::string::npos) { s.clear(); return; }
            s = s.substr(a, b - a + 1);
            };
        trim(addrStr); trim(origHex); trim(replHex);
        if (addrStr.empty() || origHex.empty() || replHex.empty()) continue;

        uint64_t addr = 0;
        {
            std::stringstream ss;
            ss << std::hex << addrStr;
            ss >> addr;
            if (!ss) continue;
        }

        if (origHex.size() > 2) origHex = origHex.substr(origHex.size() - 2);
        if (replHex.size() > 2) replHex = replHex.substr(replHex.size() - 2);

        uint8_t origByte = 0, replByte = 0;
        if (!hexByteToUint8(origHex, origByte)) continue;
        if (!hexByteToUint8(replHex, replByte)) continue;

        entries[addr] = std::make_pair(origByte, replByte);
    }

    if (entries.empty()) {
        std::cerr << "No byte entries found in file.\n";
        return false;
    }

    // Group consecutive addresses into sequences
    std::vector<uint64_t> addrs;
    addrs.reserve(entries.size());
    for (auto& kv : entries) addrs.push_back(kv.first);
    std::sort(addrs.begin(), addrs.end());

    size_t i = 0;
    while (i < addrs.size()) {
        uint64_t start = addrs[i];
        Sequence seq;
        seq.startAddr = start;
        seq.orig.push_back(entries[start].first);
        seq.repl.push_back(entries[start].second);
        uint64_t prev = start;
        ++i;
        while (i < addrs.size() && addrs[i] == prev + 1) {
            uint64_t a = addrs[i];
            seq.orig.push_back(entries[a].first);
            seq.repl.push_back(entries[a].second);
            prev = a;
            ++i;
        }
        sequences.push_back(std::move(seq));
    }

    return true;
}

// ----------------- scanning -----------------
uintptr_t scanMemory(HANDLE hProcess, const std::vector<uint8_t>& pattern) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t maxAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi;
    while (baseAddress < maxAddress) {
        SIZE_T ret = VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(baseAddress), &mbi, sizeof(mbi));
        if (ret == 0) break;

        if (mbi.State == MEM_COMMIT && (mbi.Protect & EXECUTABLE_PROTECTIONS) != 0) {
            SIZE_T regionSize = mbi.RegionSize;
            if (regionSize == 0) { baseAddress += mbi.RegionSize; continue; }

            // defensive: avoid huge single allocation if region very large
            if (regionSize > (1ULL << 30)) regionSize = (1ULL << 30); // cap 1 GiB

            std::unique_ptr<char[]> buffer(new (std::nothrow) char[regionSize]);
            if (!buffer) { baseAddress += mbi.RegionSize; continue; }

            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress), buffer.get(), regionSize, &bytesRead) && bytesRead > 0) {
                uint8_t* buf = reinterpret_cast<uint8_t*>(buffer.get());
                for (SIZE_T i = 0; i + pattern.size() <= bytesRead; ++i) {
                    bool match = true;
                    for (size_t j = 0; j < pattern.size(); ++j) {
                        if (buf[i + j] != pattern[j]) { match = false; break; }
                    }
                    if (match) return baseAddress + i;
                }
            }
        }
        baseAddress += mbi.RegionSize;
    }
    return 0;
}

// Try to write directly at the absolute address (may fail due to ASLR or protections)
bool tryDirectWrite(HANDLE hProcess, uint64_t absoluteAddr, const std::vector<uint8_t>& findBytes, const std::vector<uint8_t>& replaceBytes) {
    // First, read bytes at that address to verify original matches
    std::vector<uint8_t> readBuf(findBytes.size());
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(absoluteAddr), readBuf.data(), readBuf.size(), &bytesRead) || bytesRead != readBuf.size()) {
        return false;
    }

    if (!std::equal(readBuf.begin(), readBuf.end(), findBytes.begin())) {
        // original doesn't match
        return false;
    }

    // Build the data to write: replacement bytes + remainder of original pattern (if replacement shorter)
    std::vector<uint8_t> toWrite;
    toWrite.insert(toWrite.end(), replaceBytes.begin(), replaceBytes.end());
    if (replaceBytes.size() < findBytes.size()) {
        toWrite.insert(toWrite.end(), findBytes.begin() + replaceBytes.size(), findBytes.end());
    }

    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(absoluteAddr), toWrite.data(), toWrite.size(), &written);
    if (!ok || written != toWrite.size()) {
        return false;
    }
    std::cout << "Direct write succeeded at 0x" << std::hex << absoluteAddr << std::dec << "\n";
    return true;
}

// Apply a sequence: try direct write to absolute address, else AOB search+patch
bool applySequence(HANDLE hProcess, const Sequence& seq) {
    // Attempt direct write using exported absolute address
    if (tryDirectWrite(hProcess, seq.startAddr, seq.orig, seq.repl)) {
        return true;
    }

    // Fallback: search process memory for the original sequence
    uintptr_t found = scanMemory(hProcess, seq.orig);
    if (found == 0) {
        std::cerr << "Sequence not found in process memory (and direct write failed). StartAddr=0x" << std::hex << seq.startAddr << std::dec << "\n";
        return false;
    }

    // Prepare write buffer
    std::vector<uint8_t> toWrite;
    toWrite.insert(toWrite.end(), seq.repl.begin(), seq.repl.end());
    if (seq.repl.size() < seq.orig.size()) {
        toWrite.insert(toWrite.end(), seq.orig.begin() + seq.repl.size(), seq.orig.end());
    }

    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(found), toWrite.data(), toWrite.size(), &written);
    if (!ok || written != toWrite.size()) {
        std::cerr << "Failed to write patch at found address 0x" << std::hex << found << " (err " << GetLastError() << ")\n" << std::dec;
        return false;
    }

    std::cout << "Patched sequence at found address 0x" << std::hex << found << std::dec << "\n";
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: loader.exe \"C:\\path\\to\\target.exe\" \"C:\\path\\to\\patches.txt\"\n";
        return 1;
    }

    std::string targetPath = argv[1];
    std::string patchesFile = argv[2];

    std::string moduleName;
    std::vector<Sequence> sequences;
    if (!parseX64dbgExport(patchesFile, moduleName, sequences)) {
        std::cerr << "Failed to parse patches file.\n";
        return 1;
    }

    // Prepare mutable command line
    std::vector<char> cmdlineBuf(targetPath.begin(), targetPath.end());
    cmdlineBuf.push_back('\0');

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL created = CreateProcessA(nullptr, cmdlineBuf.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi);
    if (!created) {
        std::cerr << "Error starting application: CreateProcess failed with code " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "Started '" << targetPath << "' (PID " << pi.dwProcessId << "). Waiting for it to initialize...\n";
    Sleep(3000); // give it time to unpack/init if needed

    HANDLE hProcess = pi.hProcess;
    if (!hProcess) {
        DWORD desired = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
        hProcess = OpenProcess(desired, FALSE, pi.dwProcessId);
        if (!hProcess) {
            std::cerr << "Error: Could not open process (err " << GetLastError() << ")\n";
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 1;
        }
    }

    // Apply sequences
    size_t success = 0;
    for (const auto& seq : sequences) {
        bool ok = applySequence(hProcess, seq);
        if (ok) ++success;
    }

    std::cout << "Patching finished: " << success << " / " << sequences.size() << " sequences applied.\n";

    // Clean up
    CloseHandle(hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}