// Read x64dbg exported byte patch list (second arg) and apply patches to a launched process (first arg).
// robust module-base handling — find the module by name from the export and add its base to exported RVAs.
//
// Usage:
//   loader.exe "C:\path\to\target.exe" "C:\path\to\patches.txt"
//
// Build:
//   cl /EHsc /W4 /O2 loader.cpp Psapi.lib

#include <windows.h>
#include <psapi.h>          // EnumProcessModules, GetModuleBaseNameA
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
#include <locale>

struct Sequence {
    uint64_t startAddr;
    std::vector<uint8_t> orig;
    std::vector<uint8_t> repl;
};

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

static inline std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// Extract filename (strip path) and lower-case
static inline std::string filenameOnlyLower(const std::string& pathOrName) {
    size_t p1 = pathOrName.find_last_of("\\/");
    std::string name = (p1 == std::string::npos) ? pathOrName : pathOrName.substr(p1 + 1);
    return toLower(name);
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

// Pretty print sequences
void printSequences(const std::vector<Sequence>& sequences, const std::string& moduleName) {
    std::cout << "Module from export: '" << moduleName << "'\n";
    std::cout << "Parsed " << sequences.size() << " sequences:\n";
    for (size_t i = 0; i < sequences.size(); ++i) {
        const Sequence& s = sequences[i];
        std::cout << "[" << i << "] startAddr=0x" << std::hex << s.startAddr << std::dec
            << "  orig.size=" << s.orig.size() << " repl.size=" << s.repl.size() << "  ";
        std::cout << "orig=";
        for (size_t j = 0; j < s.orig.size(); ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)s.orig[j];
            if (j + 1 < s.orig.size()) std::cout << ' ';
        }
        std::cout << std::dec << "  repl=";
        for (size_t j = 0; j < s.repl.size(); ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)s.repl[j];
            if (j + 1 < s.repl.size()) std::cout << ' ';
        }
        std::cout << std::dec << "\n";
    }
}

// ----------------- scanning (chunked, defensive) -----------------
static void logErr(const char* msg) {
    DWORD e = GetLastError();
    std::cerr << msg << " (GetLastError=" << e << ")\n";
}

uintptr_t scanMemory(HANDLE hProcess, const std::vector<uint8_t>& pattern) {
    if (pattern.empty()) return 0;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t maxAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi;
    const SIZE_T MAX_CHUNK = 64 * 1024 * 1024; // 64 MiB

    while (baseAddress < maxAddress) {
        SIZE_T ret = VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(baseAddress), &mbi, sizeof(mbi));
        if (ret == 0) {
            baseAddress += si.dwPageSize;
            continue;
        }

        if (mbi.State == MEM_COMMIT && (mbi.Protect & EXECUTABLE_PROTECTIONS) != 0) {
            SIZE_T regionSize = mbi.RegionSize;
            if (regionSize == 0) { baseAddress += mbi.RegionSize; continue; }

            uintptr_t chunkBase = baseAddress;
            while (chunkBase < baseAddress + mbi.RegionSize) {
                SIZE_T remaining = static_cast<SIZE_T>((baseAddress + mbi.RegionSize) - chunkBase);
                SIZE_T toRead = (remaining > MAX_CHUNK) ? MAX_CHUNK : remaining;

                std::unique_ptr<char[]> buffer(new (std::nothrow) char[toRead]);
                if (!buffer) { break; } // allocation failed - skip region

                SIZE_T bytesRead = 0;
                if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(chunkBase), buffer.get(), toRead, &bytesRead) || bytesRead == 0) {
                    chunkBase += toRead;
                    continue;
                }

                uint8_t* buf = reinterpret_cast<uint8_t*>(buffer.get());
                if (bytesRead >= pattern.size()) {
                    SIZE_T limit = bytesRead - static_cast<SIZE_T>(pattern.size()) + 1;
                    for (SIZE_T i = 0; i < limit; ++i) {
                        bool match = true;
                        for (size_t j = 0; j < pattern.size(); ++j) {
                            if (buf[i + j] != pattern[j]) { match = false; break; }
                        }
                        if (match) return chunkBase + i;
                    }
                }

                chunkBase += toRead;
            }
        }

        baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return 0;
}

// Try direct write to absolute address; defensive checks
bool tryDirectWrite(HANDLE hProcess, uint64_t absoluteAddr, const std::vector<uint8_t>& findBytes, const std::vector<uint8_t>& replaceBytes) {
    if (absoluteAddr == 0) return false;
    if (findBytes.empty()) return false;
    if (absoluteAddr < 0x10000ULL) return false; // likely invalid small address

    std::vector<uint8_t> readBuf(findBytes.size());
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(absoluteAddr), readBuf.data(), readBuf.size(), &bytesRead)) {
        // read failed; bail
        //logErr("tryDirectWrite: ReadProcessMemory failed");
        return false;
    }
    if (bytesRead != readBuf.size()) return false;

    if (!std::equal(readBuf.begin(), readBuf.end(), findBytes.begin())) return false;

    std::vector<uint8_t> toWrite;
    toWrite.insert(toWrite.end(), replaceBytes.begin(), replaceBytes.end());
    if (replaceBytes.size() < findBytes.size())
        toWrite.insert(toWrite.end(), findBytes.begin() + replaceBytes.size(), findBytes.end());

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(absoluteAddr), toWrite.data(), toWrite.size(), &written) || written != toWrite.size()) {
        //logErr("tryDirectWrite: WriteProcessMemory failed");
        return false;
    }

    std::cout << "Direct write succeeded at 0x" << std::hex << absoluteAddr << std::dec << "\n";
    return true;
}

// Find module base of module whose filename matches moduleName (case-insensitive).
// If moduleName is empty or not found returns 0.
uintptr_t findModuleBaseByName(HANDLE hProcess, const std::string& moduleName) {
    if (moduleName.empty()) return 0;

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        // Try again with lower privileges? Just return 0
        return 0;
    }

    size_t modCount = cbNeeded / sizeof(HMODULE);
    std::string target = filenameOnlyLower(moduleName);

    char nameBuf[MAX_PATH];
    for (size_t i = 0; i < modCount; ++i) {
        if (GetModuleBaseNameA(hProcess, hMods[i], nameBuf, sizeof(nameBuf) / sizeof(nameBuf[0]))) {
            std::string thisName = filenameOnlyLower(std::string(nameBuf));
            if (thisName == target) {
                return reinterpret_cast<uintptr_t>(hMods[i]);
            }
        }
    }
    return 0;
}

// Apply a sequence: try direct write at moduleBase+RVA when appropriate, else AOB search+patch.
// moduleBase may be 0 (unknown) in which case only absolute direct writes (if large) or AOB will be used.
bool applySequence(HANDLE hProcess, const Sequence& seq, uintptr_t moduleBase) {
    if (seq.orig.empty() || seq.repl.empty()) {
        std::cerr << "applySequence: empty orig/repl\n";
        return false;
    }

    uint64_t exportedAddr = seq.startAddr;
    uint64_t absoluteAddr = exportedAddr;

    // Heuristic: addresses that look like small RVAs (e.g., < 0x01000000) are treated as RVAs
    if (moduleBase != 0 && exportedAddr != 0 && exportedAddr < 0x01000000ULL) {
        absoluteAddr = moduleBase + exportedAddr;
    }

    // Try direct write with the computed absolute address (if plausible)
    if (absoluteAddr != 0 && tryDirectWrite(hProcess, absoluteAddr, seq.orig, seq.repl)) {
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
    if (seq.repl.size() < seq.orig.size())
        toWrite.insert(toWrite.end(), seq.orig.begin() + seq.repl.size(), seq.orig.end());

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

    printSequences(sequences, moduleName);

    // Prepare mutable command line (only exe path by default)
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
    Sleep(3000); // give it time to init

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

    // Find module base by moduleName (robust) — if not found we will fall back to AOB patching
    uintptr_t moduleBase = findModuleBaseByName(hProcess, moduleName);
    if (moduleBase != 0) {
        std::cout << "Found module '" << moduleName << "' base: 0x" << std::hex << moduleBase << std::dec << "\n";
    }
    else {
        std::cerr << "Warning: could not find module '" << moduleName << "' in target process. Direct writes using RVAs will be skipped.\n";
    }

    // Apply sequences
    size_t success = 0;
    for (const auto& seq : sequences) {
        bool ok = applySequence(hProcess, seq, moduleBase);
        if (ok) ++success;
    }

    std::cout << "Patching finished: " << success << " / " << sequences.size() << " sequences applied.\n";

    // Clean up
    CloseHandle(hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
