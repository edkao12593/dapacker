#include <windows.h>
#include <share.h>
#include <cstdio>
#include <cwchar>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include "stub_bytes.h"
#include "aesgcm.h"

#pragma comment(lib, "Bcrypt.lib")

using namespace std;                 
namespace fs = std::filesystem;      
// 這程式是拿來打包payload到stub中
// 檔尾封裝格式：[stub]+[name(UTF-16LE)]+[nonce(12)]+[tag(16)]+[key(32)]+[ciphertext]+[Trailer]
#pragma pack(push,1)
struct Trailer {
    char     magic[4];        // "IPK2"
    uint32_t nameBytes;       // UTF-16LE bytes of payload name
    uint32_t nonceLen;        
    uint32_t tagLen;         
    uint32_t keyLen;          
    unsigned long long ctLen; // ciphertext length
};
#pragma pack(pop)

int wmain(int argc, wchar_t** argv) {
    wstring stubPath, inPath, outPath, outDir, nameArg, keyHex;

    // 參數解析
    for (int i = 1; i < argc; ++i) {
        wstring a = argv[i];
        if (a == L"--stub"   && i+1 < argc) stubPath = argv[++i];
        else if (a == L"--in"     && i+1 < argc) inPath   = argv[++i];
        else if (a == L"--out"    && i+1 < argc) outPath  = argv[++i];
        else if (a == L"--outdir" && i+1 < argc) outDir   = argv[++i];
        else if (a == L"--name"   && i+1 < argc) nameArg  = argv[++i];
        else if (a == L"--keyhex" && i+1 < argc) keyHex   = argv[++i];
    }

    
    if (inPath.empty()) {
        wprintf(L"Usage:\n  packer.exe --in payload.exe [--name hello.exe] [--out <file>|--outdir <folder>] [--keyhex 64hex]\n");
        return 1;
    }

    // 取檔名,stem,讀檔,hex to bytes
    auto Stem = [](const wstring& p)->wstring { fs::path x(p); return x.stem().wstring(); };
    auto ReadAll = [](const wstring& p, vector<unsigned char>& out)->bool {
        FILE* f = _wfsopen(p.c_str(), L"rb", _SH_DENYNO);
        if (!f) return false;
        fseek(f, 0, SEEK_END); long sz = ftell(f);
        if (sz < 0) { fclose(f); return false; }
        fseek(f, 0, SEEK_SET);
        out.resize((size_t)sz);
        size_t got = fread(out.data(), 1, out.size(), f);
        fclose(f);
        return got == out.size();
    };
    auto HexToBytes = [](const wstring& hex, vector<unsigned char>& out)->bool {
        if (hex.size() % 2) return false;
        out.clear(); out.reserve(hex.size()/2);
        auto hv=[](wchar_t c)->int{
            if(c>=L'0'&&c<=L'9')return c-L'0';
            if(c>=L'a'&&c<=L'f')return c-L'a'+10;
            if(c>=L'A'&&c<=L'F')return c-L'A'+10;
            return -1;
        };
        for(size_t i=0;i<hex.size();i+=2){
            int h=hv(hex[i]), l=hv(hex[i+1]); if(h<0||l<0) return false;
            out.push_back((unsigned char)((h<<4)|l));
        }
        return true;
    };

    // 內嵌到殼的落地檔名
    wstring payloadName = nameArg.empty() ? (Stem(inPath) + L".exe") : nameArg;
    wstring stem = Stem(payloadName);

    // 決定輸出路徑
    if (outPath.empty()) {
        if (outDir.empty()) outDir = L".";
        fs::create_directories(outDir);
        outPath = (fs::path(outDir) / (stem + L"_protected.exe")).wstring();
    } else {
        fs::create_directories(fs::path(outPath).parent_path());
        outDir = fs::path(outPath).parent_path().wstring();
        if (outDir.empty()) outDir = L".";
    }

    // 讀入stub與payload明文
    vector<unsigned char> stub, plain;

    if (!stubPath.empty()) {
        if (!ReadAll(stubPath, stub)) return 2;
    } else {
        // 預設使用內嵌的 stub
        stub.assign(STUB, STUB + STUB_SIZE);
    }

    if (!ReadAll(inPath, plain)) return 3;

    // 準備key/Nonce
    vector<unsigned char> key;
    if (!keyHex.empty()) {
        if (!HexToBytes(keyHex, key) || key.size()!=32) { wprintf(L"keyhex must be 64 hex chars (32 bytes)\n"); return 4; }
    } else {
        key.assign(32, 0);
        if (!RandomBytes(key.data(), key.size())) { wprintf(L"random key failed\n"); return 5; }
    }
    unsigned char nonce[12];
    if (!RandomBytes(nonce, sizeof(nonce))) { wprintf(L"random nonce failed\n"); return 6; }

    // AES-GCM加密
    vector<unsigned char> ct, tag;
    if (!AESGCM_Encrypt(key.data(), key.size(), nonce, sizeof(nonce), plain.data(), plain.size(), ct, tag)) {
        wprintf(L"encrypt failed\n"); return 7;
    }

    // 寫出：單一handle串寫（避免多次開關檔）
    FILE* fo = _wfsopen(outPath.c_str(), L"wb", _SH_DENYNO);
    if (!fo) { wprintf(L"open out failed\n"); return 8; }
    auto put = [&](const void* p, size_t n)->bool { return fwrite(p,1,n,fo)==n; };

    size_t nameBytes = payloadName.size() * sizeof(wchar_t);
    if (!put(stub.data(), stub.size()))                    { fclose(fo); wprintf(L"write stub failed\n"); return 9; }
    if (!put(payloadName.data(), nameBytes))               { fclose(fo); wprintf(L"append name failed\n"); return 10; }
    if (!put(nonce, sizeof(nonce)))                        { fclose(fo); wprintf(L"append nonce failed\n"); return 11; }
    if (!put(tag.data(), 16))                              { fclose(fo); wprintf(L"append tag failed\n"); return 12; } // 固定 16
    if (!put(key.data(), 32))                              { fclose(fo); wprintf(L"append key failed\n"); return 13; } // 固定 32
    if (!ct.empty() && !put(ct.data(), ct.size()))         { fclose(fo); wprintf(L"append ct failed\n"); return 14; }

    // Trailer
    Trailer tr{};
    memcpy(tr.magic, "IPK2", 4);
    tr.nameBytes = (uint32_t)nameBytes;
    tr.nonceLen  = 12;
    tr.tagLen    = 16;
    tr.keyLen    = 32;
    tr.ctLen     = (unsigned long long)ct.size();
    if (!put(&tr, sizeof(tr)))             { fclose(fo); wprintf(L"append trailer failed\n"); return 15; }

    fclose(fo);

    // 另存金鑰檔
    fs::path keyHexPath = fs::path(outDir) / (stem + L"_key.key");
    fs::path keyBinPath = fs::path(outDir) / (stem + L"_key.bin");

    if (FILE* fhex = _wfsopen(keyHexPath.c_str(), L"wb", _SH_DENYNO)) {
        static const wchar_t* hexmap = L"0123456789abcdef";
        for (unsigned char b : key) { wchar_t w[2] = { hexmap[(b>>4)&0xF], hexmap[b&0xF] }; fputwc(w[0], fhex); fputwc(w[1], fhex); }
        fputwc(L'\n', fhex); fclose(fhex);
    }
    if (FILE* fbin = _wfsopen(keyBinPath.c_str(), L"wb", _SH_DENYNO)) {
        fwrite(key.data(), 1, key.size(), fbin); fclose(fbin);
    }

    wprintf(L"OK -> %s\n", outPath.c_str());
    return 0;
}
