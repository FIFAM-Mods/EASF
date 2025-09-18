#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

struct EASF_header {
    unsigned int signature;
    unsigned int decryptedSize;
    char keyid[8];
    unsigned char digest[32];
};

std::vector<unsigned char> aes_128_cbc_decrypt(
    std::vector<unsigned char>const& cipherdata, const unsigned char key[16], const unsigned char iv[16])
{
    std::vector<unsigned char> result(cipherdata.size() + AES_BLOCK_SIZE);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return result;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv)) return result;
    int outlen1 = 0;
    if (1 != EVP_DecryptUpdate(ctx, result.data(), &outlen1, cipherdata.data(), (int)cipherdata.size())) {
        result.clear();
        return result;
    }
    int outlen2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, result.data() + outlen1, &outlen2)) {
        result.clear();
        return result;
    }
    result.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::vector<unsigned char> aes_128_cbc_encrypt(
    std::vector<unsigned char>const& data, const unsigned char key[16], const unsigned char iv[16])
{
    std::vector<unsigned char> result(data.size() + AES_BLOCK_SIZE);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return result;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv)) return result;
    int outlen1 = 0;
    if (1 != EVP_EncryptUpdate(ctx, result.data(), &outlen1, data.data(), (int)data.size())) {
        result.clear();
        return result;
    }
    int outlen2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, result.data() + outlen1, &outlen2)) {
        result.clear();
        return result;
    }
    result.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::vector<unsigned char> sha256(const unsigned char* data, size_t len) {
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(data, len, digest.data());
    return digest;
}

std::vector<unsigned char> get_key(std::wstring const &game) {
    if (game == L"fifa15" || game == L"fifa16")
        return { 0x24, 0x9B, 0xF2, 0x7A, 0xF5, 0xD7, 0x48, 0x7B, 0x15, 0x78, 0xD8, 0x33, 0xF2, 0xDE, 0x39, 0xB5 };
    return { 0x24, 0x91, 0x85, 0xE3, 0x70, 0x7B, 0xD8, 0x83, 0xCE, 0xA5, 0xC5, 0x11, 0xF5, 0xD4, 0x67, 0xF2 };
}

extern "C" unsigned __int64 _dtoul3_legacy(double v) { return (unsigned __int64)llround(v); }

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 4)
        return 1;
    FILE* fi = nullptr;
    _wfopen_s(&fi, argv[2], L"rb");
    if (!fi)
        return 1;
    fseek(fi, 0, SEEK_END);
    auto dataSize = ftell(fi);
    fseek(fi, 0, SEEK_SET);
#ifdef _DECRYPTOR
    if (dataSize < 48)
        return 0;
    EASF_header header;
    fread(&header, sizeof(EASF_header), 1, fi);
    if (header.signature != 'FSAE' || strncmp(header.keyid, "datax   ", 8))
        return 1;
    header.decryptedSize = _byteswap_ulong(header.decryptedSize);
    dataSize -= sizeof(EASF_header);
#endif
    std::vector<unsigned char> data(dataSize);
    fread(data.data(), 1, dataSize, fi);
    fclose(fi);
    auto key = get_key(argv[1]);
#ifdef _DECRYPTOR
    auto result = aes_128_cbc_decrypt(data, key.data(), key.data());
    if (result.size() > header.decryptedSize)
        result.resize(header.decryptedSize);
#else
    auto result = aes_128_cbc_encrypt(data, key.data(), key.data());
#endif
    if (result.empty())
        return 1;
    FILE* fo = nullptr;
    _wfopen_s(&fo, argv[3], L"wb");
    if (!fo)
        return 1;
#ifdef _ENCRYPTOR
    EASF_header header;
    header.signature = 'FSAE';
    header.decryptedSize = _byteswap_ulong(dataSize);
    memcpy(header.keyid, "datax   ", 8);
    memcpy(header.digest, sha256(data.data(), 32).data(), 32);
    fwrite(&header, 1, sizeof(EASF_header), fo);
#endif
    fwrite(result.data(), 1, result.size(), fo);
    fclose(fo);
    return 0;
}
