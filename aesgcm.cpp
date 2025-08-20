#include "aesgcm.h"
#include <bcrypt.h>
#include <vector>
#pragma comment(lib, "Bcrypt.lib")

using namespace std;  
// 這程式提供AES-GCM加密和解密功能
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

bool RandomBytes(unsigned char* buf, size_t len) {
    return NT_SUCCESS(BCryptGenRandom(nullptr, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

static bool OpenAesGcm(BCRYPT_ALG_HANDLE& hAlg) {
    NTSTATUS s = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(s)) return false;
    s = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(s)) { BCryptCloseAlgorithmProvider(hAlg, 0); hAlg = nullptr; return false; }
    return true;
}

bool AESGCM_Encrypt(const unsigned char* key, size_t keyLen,
                    const unsigned char* nonce, size_t nonceLen,
                    const unsigned char* plaintext, size_t ptLen,
                    vector<unsigned char>& outCipher,
                    vector<unsigned char>& outTag) {
    if (!key || !nonce || !plaintext) return false;
    if (keyLen != 32 || nonceLen != 12 || ptLen == 0) return false;  // 固定規格

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!OpenAesGcm(hAlg)) return false;

    DWORD cbObj = 0, cbRes = 0;
    PUCHAR keyObj = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    ULONG cbOut = 0;               
    bool ok = false;

    // 準備金鑰物件空間
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(cbObj), &cbRes, 0))) goto done;
    keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbObj); if (!keyObj) goto done;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, cbObj, (PUCHAR)key, (ULONG)keyLen, 0))) goto done;

    // 設定GCM的Nonce/Ta緩衝區
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR)nonce; ai.cbNonce = (ULONG)nonceLen;

    outCipher.assign(ptLen, 0);
    outTag.assign(16, 0);               
    ai.pbTag = outTag.data(); ai.cbTag = 16;

    // 加密
    if (!NT_SUCCESS(BCryptEncrypt(hKey,
                                  (PUCHAR)plaintext, (ULONG)ptLen,
                                  &ai,
                                  nullptr, 0,
                                  outCipher.data(), (ULONG)outCipher.size(),
                                  &cbOut,
                                  0))) goto done;

    outCipher.resize(cbOut);
    ok = true;

done:
    if (hKey)   BCryptDestroyKey(hKey);
    if (keyObj) HeapFree(GetProcessHeap(), 0, keyObj);
    if (hAlg)   BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// 解密
bool AESGCM_Decrypt(const unsigned char* key, size_t keyLen,
                    const unsigned char* nonce, size_t nonceLen,
                    const unsigned char* ciphertext, size_t ctLen,
                    const unsigned char* tag, size_t tagLen,
                    vector<unsigned char>& outPlain) {
    if (!key || !nonce || !ciphertext || !tag) return false;
    if (keyLen != 32 || nonceLen != 12 || tagLen != 16) return false;  // 固定規格

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!OpenAesGcm(hAlg)) return false;

    DWORD cbObj = 0, cbRes = 0;
    PUCHAR keyObj = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    ULONG cbOut = 0;                   
    bool ok = false;

    // 準備金鑰物件空間
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(cbObj), &cbRes, 0))) goto done;
    keyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbObj); if (!keyObj) goto done;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj, cbObj, (PUCHAR)key, (ULONG)keyLen, 0))) goto done;

    // 設GCM的Nonce/Tag緩衝區
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai; BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR)nonce; ai.cbNonce = (ULONG)nonceLen;
    ai.pbTag   = (PUCHAR)tag;   ai.cbTag   = 16;

    // 執行解密和驗證Tag
    outPlain.assign(ctLen, 0);
    if (!NT_SUCCESS(BCryptDecrypt(hKey,
                                  (PUCHAR)ciphertext, (ULONG)ctLen,
                                  &ai,
                                  nullptr, 0,
                                  outPlain.data(), (ULONG)outPlain.size(),
                                  &cbOut,
                                  0))) goto done;

    outPlain.resize(cbOut);
    ok = true;

done:
    if (hKey)   BCryptDestroyKey(hKey);
    if (keyObj) HeapFree(GetProcessHeap(), 0, keyObj);
    if (hAlg)   BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}
