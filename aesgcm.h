#pragma once
#include <vector>
#include <windows.h>

bool RandomBytes(unsigned char* buf, size_t len); 

bool AESGCM_Encrypt(const unsigned char* key, size_t keyLen,
                    const unsigned char* nonce, size_t nonceLen,
                    const unsigned char* plaintext, size_t ptLen,
                    std::vector<unsigned char>& outCipher,
                    std::vector<unsigned char>& outTag);

bool AESGCM_Decrypt(const unsigned char* key, size_t keyLen,
                    const unsigned char* nonce, size_t nonceLen,
                    const unsigned char* ciphertext, size_t ctLen,
                    const unsigned char* tag, size_t tagLen,
                    std::vector<unsigned char>& outPlain);
