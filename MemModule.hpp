/*
* 作者：NightCat[洛小米]
* 
* 联系方式：fengbai0806qq.com
* 
*/


#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <algorithm>

namespace MemIO
{
    //------------------------------------------------------
    // 全局
    //------------------------------------------------------
    inline DWORD g_pid = 0;
    inline HANDLE g_hProc = nullptr;


    inline BYTE g_WPM_Orig[5] = { 0 };   // stub 只有 5 字节
    inline SIZE_T g_WPM_Size = 5;     // x64/x86 stub 长度

    // 初始化：保存原始 stub
    inline void InitAntiSteal()
    {
        FARPROC proc = GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
            "WriteProcessMemory");
        if (!proc) throw std::runtime_error("InitAntiSteal: GetProcAddress");

        ReadProcessMemory(GetCurrentProcess(), proc, g_WPM_Orig,
            g_WPM_Size, &g_WPM_Size);
    }

    // 是否出现 JMP / CALL 指令
    [[nodiscard]] inline bool IsStubHooked()
    {
        FARPROC proc = GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
            "WriteProcessMemory");
        if (!proc) return false;

        BYTE curr[5] = { 0 };
        SIZE_T read = 0;
        ReadProcessMemory(GetCurrentProcess(), proc, curr,
            sizeof(curr), &read);

        // 1. 直接比对 5 字节
        bool changed = (memcmp(g_WPM_Orig, curr, sizeof(curr)) != 0);

        // 2. 检测 JMP / CALL 指令
        bool hook = (curr[0] == 0xE9) ||                 // jmp rel32
            (curr[0] == 0xE8) ||                 // call rel32
            (curr[0] == 0xFF);                   // jmp/call [rip+rel32]

        return changed || hook;
    }


    [[nodiscard]] inline void ThrowWin32(const char* msg)
    {
        throw std::runtime_error(std::string(msg) +
            " (GLE=" + std::to_string(GetLastError()) + ")");
    }

    //------------------------------------------------------
    // 1. 设置进程（唯一入口：进程名）
    //------------------------------------------------------
    inline void SetPID(const std::wstring& processName)
    {
        // 先关闭旧句柄
        if (g_hProc) { CloseHandle(g_hProc); g_hProc = nullptr; }

        // 通过进程名找 PID
        DWORD pid = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) ThrowWin32("CreateToolhelp32Snapshot");
        PROCESSENTRY32W pe{ .dwSize = sizeof(pe) };
        for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        {
            if (!_wcsicmp(pe.szExeFile, processName.c_str()))
            {
                pid = pe.th32ProcessID;
                break;
            }
        }
        CloseHandle(snap);
        if (!pid) throw std::runtime_error("process not found");

        // 打开句柄
        g_hProc = ::OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!g_hProc) ThrowWin32("OpenProcess");
        g_pid = pid;
    }

    //------------------------------------------------------
    // 2. 模块基址
    //------------------------------------------------------
    [[nodiscard]] inline uintptr_t GetModule(const std::wstring& moduleName)
    {
        if (!g_pid) throw std::runtime_error("call SetPID first");
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
        if (snap == INVALID_HANDLE_VALUE) ThrowWin32("CreateToolhelp32Snapshot MODULE");
        MODULEENTRY32W me{ .dwSize = sizeof(me) };
        uintptr_t base = 0;
        for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me))
        {
            if (!_wcsicmp(me.szModule, moduleName.c_str()))
            {
                base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        }
        CloseHandle(snap);
        if (!base) throw std::runtime_error("module not found");
        return base;
    }

    //------------------------------------------------------
    // 3. 字节级读写
    //------------------------------------------------------
    inline void ReadRaw(uintptr_t addr, void* buf, SIZE_T sz)
    {
        SIZE_T read = 0;
        if (!ReadProcessMemory(g_hProc, reinterpret_cast<LPCVOID>(addr), buf, sz, &read) || read != sz)
            ThrowWin32("ReadProcessMemory");
    }

    inline void WriteRaw(uintptr_t addr, const void* buf, SIZE_T sz)
    {
        SIZE_T written = 0;
        if (!WriteProcessMemory(g_hProc, reinterpret_cast<LPVOID>(addr), buf, sz, &written) || written != sz)
            ThrowWin32("WriteProcessMemory");
    }

    template<typename T>
    [[nodiscard]] inline T Read(uintptr_t addr)
    {
        T val{};
        ReadRaw(addr, &val, sizeof(T));
        return val;
    }

    template<typename T>
    inline void Write(uintptr_t addr, const T& v)
    {
        WriteRaw(addr, &v, sizeof(T));
    }

    template <typename T = uintptr_t>
    [[nodiscard]] inline T ReadChain(uintptr_t base,
        const std::vector<uintptr_t>& offsets)
    {
        uintptr_t addr = base;
        for (size_t level = 0; level < offsets.size(); ++level)
        {
            addr += offsets[level];
            if (level + 1 < offsets.size())
            {
                addr = MemIO::Read<uintptr_t>(addr);
                if (!addr) throw std::runtime_error("null pointer at level " + std::to_string(level));
            }
        }
        return MemIO::Read<T>(addr);
    }

    // ------------------------------------------------------
    // 读取以 \0 结尾的 UTF-16 宽字符串并返回 UTF-8 std::string
    // ------------------------------------------------------
    [[nodiscard]] inline std::string ReadWstring(uintptr_t addr, size_t maxLen = 512)
    {
        if (maxLen == 0 || maxLen > 4096)
            throw std::runtime_error("ReadWstring: invalid maxLen");

        std::vector<wchar_t> buf(maxLen);
        ReadRaw(addr, buf.data(), maxLen * sizeof(wchar_t));

        // 找到首个 L'\0'
        auto end = std::find(buf.begin(), buf.end(), L'\0');
        std::wstring wstr(buf.begin(), end);

        if (wstr.empty()) return {};

        // UTF-16 -> UTF-8
        int u8len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
            nullptr, 0, nullptr, nullptr);
        if (u8len <= 0) throw std::runtime_error("ReadWstring: UTF-16->UTF-8 failed");

        std::string u8(u8len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
            u8.data(), u8len, nullptr, nullptr);
        u8.pop_back();   // 去掉末尾 '\0'
        return u8;
    }

    [[nodiscard]] inline std::string ReadString(uintptr_t addr, size_t maxLen = 512)
    {
        if (maxLen == 0 || maxLen > 4096)
            throw std::runtime_error("ReadString: invalid maxLen");

        std::vector<char> buf(maxLen);
        ReadRaw(addr, buf.data(), maxLen);

        // 找到结尾 '\0'
        auto end = std::find(buf.begin(), buf.end(), '\0');
        std::string ansi(buf.begin(), end);

        if (ansi.empty()) return {};

        // 当前系统代码页 -> UTF-8
        int wlen = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, nullptr, 0);
        if (wlen <= 0) return ansi;            // 无法转码，原样返回
        std::wstring wstr(wlen, 0);
        MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, wstr.data(), wlen);

        int u8len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
            nullptr, 0, nullptr, nullptr);
        if (u8len <= 0) return ansi;
        std::string u8(u8len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1,
            u8.data(), u8len, nullptr, nullptr);
        u8.pop_back();   // 去掉末尾 '\0'
        return u8;
    }

    //------------------------------------------------------
    // 4. 特征码搜索（支持 ?? 通配符）
    //------------------------------------------------------
    [[nodiscard]] inline std::pair<std::vector<uint8_t>, std::vector<bool>>
        ParseSig(const std::string& pat)
    {
        std::vector<uint8_t> bytes;
        std::vector<bool> mask;
        std::istringstream iss(pat);
        std::string tok;
        while (iss >> tok)
        {
            if (tok == "??") { bytes.push_back(0); mask.push_back(false); }
            else if (tok.size() == 2 && std::isxdigit(tok[0]) && std::isxdigit(tok[1]))
            {
                bytes.push_back(static_cast<uint8_t>(std::stoi(tok, nullptr, 16)));
                mask.push_back(true);
            }
            else throw std::runtime_error("invalid token: " + tok);
        }
        return { bytes, mask };
    }

    [[nodiscard]] inline size_t Find(const uint8_t* data, size_t len,
        const std::vector<uint8_t>& sig,
        const std::vector<bool>& mask)
    {
        const size_t n = sig.size();
        if (len < n) return SIZE_MAX;

        for (size_t i = 0; i <= len - n; ++i)
        {
            bool ok = true;
            for (size_t j = 0; j < n; ++j)
            {
                if (mask[j] && data[i + j] != sig[j])
                {
                    ok = false;
                    break;
                }
            }
            if (ok) return i;
        }
        return SIZE_MAX;
    }

    [[nodiscard]] inline uintptr_t SigScanRange(uintptr_t start, uintptr_t end,
        const std::string& pattern)
    {
        auto [sig, mask] = ParseSig(pattern);
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        if (end == 0) end = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = start;
        while (addr < end &&
            VirtualQueryEx(g_hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
        {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
                    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
            {
                std::vector<uint8_t> buf(mbi.RegionSize);
                SIZE_T read = 0;
                if (ReadProcessMemory(g_hProc, mbi.BaseAddress, buf.data(), mbi.RegionSize, &read))
                {
                    size_t off = Find(buf.data(), read, sig, mask);
                    if (off != SIZE_MAX)
                        return reinterpret_cast<uintptr_t>(mbi.BaseAddress) + off;
                }
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        throw std::runtime_error("signature not found");
    }

    [[nodiscard]] inline uintptr_t SigScan(const std::wstring& module,
        const std::string& pattern)
    {
        uintptr_t base = GetModule(module);
        MODULEINFO mi{};
        if (!GetModuleInformation(g_hProc, reinterpret_cast<HMODULE>(base),
            &mi, sizeof(mi)))
            ThrowWin32("GetModuleInformation");
        return SigScanRange(base, base + mi.SizeOfImage, pattern);
    }

    [[nodiscard]] inline uintptr_t SigScan(const std::string& pattern)
    {
        return SigScanRange(0, 0, pattern);
    }


    template <typename T>
    [[nodiscard]] inline std::vector<uintptr_t>
        SearchArray(const T* pattern, size_t count,
            uintptr_t start = 0, uintptr_t end = 0)
    {
        static_assert(std::is_trivially_copyable_v<T>);
        const size_t patBytes = count * sizeof(T);
        std::vector<uintptr_t> hits;
        if (!pattern || !count || !g_hProc) return hits;

        SYSTEM_INFO si{}; GetSystemInfo(&si);
        if (end == 0) end = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

        MEMORY_BASIC_INFORMATION mbi{};
        uintptr_t addr = start;

        while (addr < end)
        {
            if (!VirtualQueryEx(g_hProc, (LPCVOID)addr, &mbi, sizeof(mbi))) break;

            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
            {
                // 一次整块读取，零额外拷贝
                std::vector<std::byte> buf(mbi.RegionSize);
                SIZE_T read = 0;
                if (ReadProcessMemory(g_hProc, mbi.BaseAddress,
                    buf.data(), mbi.RegionSize, &read))
                {
                    const std::byte* data = buf.data();
                    for (SIZE_T off = 0; off + patBytes <= read; ++off)
                    {
                        if (!memcmp(data + off, pattern, patBytes))
                            hits.emplace_back(addr + off);
                    }
                }
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
        return hits;
    }
} // namespace MemIO