
#ifndef NOMINMAX
#define NOMINMAX
#endif
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shell32.lib")

#include <windows.h>
#include <shellapi.h>
#include <share.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include "aesgcm.h"

using namespace std;  
// 這程式是拿來執行被保護的payload
// 尾端封裝描述(和packer.cpp一致)
#pragma pack(push,1)
struct Trailer {
    char     magic[4];      
    uint32_t nameBytes;     
    uint32_t nonceLen;      
    uint32_t tagLen;        
    uint32_t keyLen;        
    unsigned long long ctLen;  
};
#pragma pack(pop)

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    // 執行檔讀進記憶體
    auto ReadSelfAll = [](vector<unsigned char>& out)->bool {
        wchar_t path[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return false;
        FILE* f = _wfsopen(path, L"rb", _SH_DENYNO);
        if (!f) return false;
        fseek(f, 0, SEEK_END); long sz = ftell(f);
        if (sz < 0) { fclose(f); return false; }
        fseek(f, 0, SEEK_SET);
        out.resize((size_t)sz);
        size_t got = fread(out.data(), 1, out.size(), f);
        fclose(f);
        return got == out.size();
    };
   auto GetDropDir = []()->std::wstring {
    // 落地到 %TEMP%\\IntegrityPacker 
    wchar_t tmp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    std::wstring dir = (n == 0 || n > MAX_PATH) ? L".\\" : std::wstring(tmp);
    dir += L"IntegrityPacker\\";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
};
        // 資料寫進指定檔案
    auto WriteAll = [](const wstring& path, const unsigned char* data, size_t size)->bool {
        // WinAPI分流寫入避免一次性過大
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        size_t total=0;
        while (total<size) {
            DWORD w=0; DWORD chunk = (DWORD)min<size_t>(0x10000, size-total);
            if (!WriteFile(h, data+total, chunk, &w, nullptr)) { CloseHandle(h); return false; }
            total += w;
        }
        CloseHandle(h); return true;
    };
    auto ShowErr = [](const wchar_t* title, DWORD err) {
        wchar_t buf[512];
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err, 0, buf, 512, nullptr);
        MessageBoxW(nullptr, buf, title, MB_ICONERROR);
    };
    auto QuoteArg = [](const wstring& s)->wstring {
        if (s.find_first_of(L" \t\"")==wstring::npos) return s;
        wstring o=L"\""; for(wchar_t c: s){ if(c==L'"') o+=L"\\\""; else o+=c; } o+=L"\""; return o;
    };
    // 把殼自身的參數原封不動轉交給子程式

    auto BuildChildCmd = [&](const wstring& childPath)->wstring {
        int argc=0; LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        wstring cmd = QuoteArg(childPath);
        for (int i=1;i<argc;i++){ cmd+=L" "; cmd+=QuoteArg(argv[i]); }
        if (argv) LocalFree(argv);
        return cmd;
    };

    // 讀自身完整檔案
    vector<unsigned char> me;
    if (!ReadSelfAll(me)) return 10;
    if (me.size() < sizeof(Trailer)) return 11;

    // 從檔尾取出Trailer並回推各區段
    Trailer tr{};
    memcpy(&tr, me.data() + (me.size()-sizeof(Trailer)), sizeof(Trailer));
    if (memcmp(tr.magic, "IPK2", 4)!=0) return 12;

    size_t need = (size_t)tr.nameBytes + tr.nonceLen + tr.tagLen + tr.keyLen + (size_t)tr.ctLen;
    if (me.size() < sizeof(Trailer) + need) return 13;

    size_t base = me.size() - sizeof(Trailer) - need;
    const unsigned char* p = me.data() + base;

    wstring name((const wchar_t*)p, tr.nameBytes/2); p += tr.nameBytes;
    const unsigned char* nonce = p; p += tr.nonceLen;
    const unsigned char* tag   = p; p += tr.tagLen;
    const unsigned char* key   = p; p += tr.keyLen;
    const unsigned char* ct    = p; // ctLen = tr.ctLen

    // 解密
    vector<unsigned char> plain;
    if (!AESGCM_Decrypt(key, tr.keyLen, nonce, tr.nonceLen, ct, (size_t)tr.ctLen, tag, tr.tagLen, plain)) {
        MessageBoxW(nullptr, L"Decryption failed.", L"Integrity Packer", MB_ICONERROR);
        return 20;
    }

    // 落地到暫存資料夾並啟動子程式(轉交原參數)
    wstring dir = GetDropDir();
    wstring exePath = dir + name;
    if (!WriteAll(exePath, plain.data(), plain.size())) { ShowErr(L"Write payload failed", GetLastError()); return 21; }

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    wstring cmd = BuildChildCmd(exePath);
    BOOL ok = CreateProcessW(exePath.c_str(), (LPWSTR)cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, dir.c_str(), &si, &pi);
    if (!ok) { ShowErr(L"CreateProcessW failed", GetLastError()); return 22; }

    // 等待子程式結束並回傳其 exit code
    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code=0; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);

#if IP_CLEANUP
    DeleteFileW(exePath.c_str());
#endif
    return (int)code;
}
