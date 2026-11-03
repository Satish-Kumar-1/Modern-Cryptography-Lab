#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {
using Bytes = std::vector<unsigned char>;
constexpr std::size_t KEY_SIZE = 32;
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t TAG_SIZE = 16;
constexpr std::array<unsigned char, 8> MAGIC{'S', 'F', 'E', 'G', 'C', 'M', '1', 0};
constexpr std::size_t OVERHEAD = MAGIC.size() + NONCE_SIZE + TAG_SIZE;

struct CipherPackage {
    std::array<unsigned char, NONCE_SIZE> nonce{};
    Bytes ciphertext;
    std::array<unsigned char, TAG_SIZE> tag{};
};

struct EvpContextDeleter {
    void operator()(EVP_CIPHER_CTX* context) const noexcept {
        EVP_CIPHER_CTX_free(context);
    }
};
using EvpContext = std::unique_ptr<EVP_CIPHER_CTX, EvpContextDeleter>;

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

void requireOpenSsl(int result, const std::string& operation) {
    if (result != 1) {
        fail("OpenSSL error while " + operation);
    }
}

Bytes readFile(const fs::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) fail("Cannot open file for reading: " + path.string());
    const auto end = input.tellg();
    if (end < 0) fail("Cannot determine file size: " + path.string());
    const auto size = static_cast<std::uintmax_t>(end);
    if (size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max())) {
        fail("File is too large: " + path.string());
    }
    Bytes data(static_cast<std::size_t>(size));
    input.seekg(0);
    if (!data.empty() && !input.read(reinterpret_cast<char*>(data.data()),
                                     static_cast<std::streamsize>(data.size()))) {
        fail("Cannot read complete file: " + path.string());
    }
    return data;
}

void writeFile(const fs::path& path, const Bytes& data) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) fail("Cannot open file for writing: " + path.string());
    if (!data.empty()) {
        output.write(reinterpret_cast<const char*>(data.data()),
                     static_cast<std::streamsize>(data.size()));
    }
    if (!output) fail("Cannot write complete file: " + path.string());
}

bool confirmOverwrite(const fs::path& path) {
    if (!fs::exists(path)) return true;
    std::cout << path.string() << " already exists. Overwrite? [y/N] ";
    std::string answer;
    std::getline(std::cin, answer);
    return answer == "y" || answer == "Y" || answer == "yes" || answer == "YES";
}

Bytes randomBytes(std::size_t count) {
    if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        fail("Random byte request is too large");
    }
    Bytes bytes(count);
    requireOpenSsl(RAND_bytes(bytes.data(), static_cast<int>(bytes.size())),
                   "generating secure random bytes");
    return bytes;
}

void validateEvpLength(std::size_t size) {
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        fail("Input is too large for this educational implementation");
    }
}

CipherPackage encryptBytes(const Bytes& plaintext, const Bytes& key,
                           const std::array<unsigned char, NONCE_SIZE>& nonce) {
    if (key.size() != KEY_SIZE) fail("AES-256 key must be exactly 32 bytes");
    validateEvpLength(plaintext.size());

    EvpContext context(EVP_CIPHER_CTX_new());
    if (!context) fail("Could not allocate an OpenSSL cipher context");
    requireOpenSsl(EVP_EncryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                   "selecting AES-256-GCM");
    requireOpenSsl(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                                       static_cast<int>(nonce.size()), nullptr),
                   "setting the GCM nonce length");
    requireOpenSsl(EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()),
                   "setting the AES key and nonce");

    CipherPackage package;
    package.nonce = nonce;
    package.ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int produced = 0;
    int finalProduced = 0;
    requireOpenSsl(EVP_EncryptUpdate(context.get(), package.ciphertext.data(), &produced,
                                     plaintext.data(), static_cast<int>(plaintext.size())),
                   "encrypting plaintext");
    requireOpenSsl(EVP_EncryptFinal_ex(context.get(), package.ciphertext.data() + produced,
                                       &finalProduced),
                   "finishing encryption");
    package.ciphertext.resize(static_cast<std::size_t>(produced + finalProduced));
    requireOpenSsl(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG,
                                       static_cast<int>(package.tag.size()), package.tag.data()),
                   "reading the authentication tag");
    return package;
}

bool decryptBytes(const CipherPackage& package, const Bytes& key, Bytes& plaintext) {
    plaintext.clear();
    if (key.size() != KEY_SIZE) return false;
    validateEvpLength(package.ciphertext.size());

    EvpContext context(EVP_CIPHER_CTX_new());
    if (!context) fail("Could not allocate an OpenSSL cipher context");
    requireOpenSsl(EVP_DecryptInit_ex(context.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                   "selecting AES-256-GCM");
    requireOpenSsl(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_IVLEN,
                                       static_cast<int>(package.nonce.size()), nullptr),
                   "setting the GCM nonce length");
    requireOpenSsl(EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                                      package.nonce.data()),
                   "setting the AES key and nonce");

    Bytes candidate(package.ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int produced = 0;
    if (EVP_DecryptUpdate(context.get(), candidate.data(), &produced, package.ciphertext.data(),
                          static_cast<int>(package.ciphertext.size())) != 1) {
        return false;
    }
    auto tag = package.tag;
    if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1) {
        return false;
    }
    int finalProduced = 0;
    if (EVP_DecryptFinal_ex(context.get(), candidate.data() + produced, &finalProduced) != 1) {
        return false;  // Authentication failed. Candidate plaintext is deliberately discarded.
    }
    candidate.resize(static_cast<std::size_t>(produced + finalProduced));
    plaintext = std::move(candidate);
    return true;
}

CipherPackage encryptWithFreshNonce(const Bytes& plaintext, const Bytes& key) {
    const Bytes nonceBytes = randomBytes(NONCE_SIZE);
    std::array<unsigned char, NONCE_SIZE> nonce{};
    std::copy(nonceBytes.begin(), nonceBytes.end(), nonce.begin());
    return encryptBytes(plaintext, key, nonce);
}

Bytes serialize(const CipherPackage& package) {
    Bytes data;
    data.reserve(OVERHEAD + package.ciphertext.size());
    data.insert(data.end(), MAGIC.begin(), MAGIC.end());
    data.insert(data.end(), package.nonce.begin(), package.nonce.end());
    data.insert(data.end(), package.ciphertext.begin(), package.ciphertext.end());
    data.insert(data.end(), package.tag.begin(), package.tag.end());
    return data;
}

CipherPackage parsePackage(const Bytes& data) {
    if (data.size() < OVERHEAD) fail("Encrypted file is too short or truncated");
    if (!std::equal(MAGIC.begin(), MAGIC.end(), data.begin())) {
        fail("Encrypted file has an invalid header");
    }
    CipherPackage package;
    auto cursor = data.begin() + static_cast<std::ptrdiff_t>(MAGIC.size());
    std::copy_n(cursor, NONCE_SIZE, package.nonce.begin());
    cursor += static_cast<std::ptrdiff_t>(NONCE_SIZE);
    const auto cipherLength = data.size() - OVERHEAD;
    package.ciphertext.assign(cursor, cursor + static_cast<std::ptrdiff_t>(cipherLength));
    cursor += static_cast<std::ptrdiff_t>(cipherLength);
    std::copy_n(cursor, TAG_SIZE, package.tag.begin());
    return package;
}

void encryptCommand(const fs::path& inputPath, const fs::path& encryptedPath,
                    const fs::path& keyPath) {
    if (encryptedPath == keyPath) fail("Encrypted output and key output must be different files");
    if (!confirmOverwrite(encryptedPath) || !confirmOverwrite(keyPath)) {
        fail("Operation cancelled; no files were written");
    }
    const Bytes plaintext = readFile(inputPath);
    const Bytes key = randomBytes(KEY_SIZE);
    const CipherPackage package = encryptWithFreshNonce(plaintext, key);
    writeFile(encryptedPath, serialize(package));
    try {
        writeFile(keyPath, key);
    } catch (...) {
        std::error_code ignored;
        fs::remove(encryptedPath, ignored);
        throw;
    }
    std::cout << "Encrypted " << plaintext.size() << " bytes successfully.\n";
    std::cout << "Keep " << keyPath.string() << " secret and never reuse its nonce.\n";
}

void decryptCommand(const fs::path& encryptedPath, const fs::path& keyPath,
                    const fs::path& outputPath) {
    if (!confirmOverwrite(outputPath)) fail("Operation cancelled; no file was written");
    const CipherPackage package = parsePackage(readFile(encryptedPath));
    const Bytes key = readFile(keyPath);
    if (key.size() != KEY_SIZE) fail("Key file must contain exactly 32 bytes");
    Bytes plaintext;
    if (!decryptBytes(package, key, plaintext)) {
        fail("Authentication failed: wrong key or modified encrypted data/tag. No output was written");
    }
    writeFile(outputPath, plaintext);
    std::cout << "Decrypted and authenticated " << plaintext.size() << " bytes successfully.\n";
}

bool reportTest(const std::string& name, bool passed, const std::string& explanation) {
    std::cout << (passed ? "PASS" : "FAIL") << " - " << name << ": " << explanation << '\n';
    return passed;
}

int testCommand() {
    bool allPassed = true;
    const Bytes plaintext{'S','e','c','u','r','e',' ','f','i','l','e',' ','t','e','s','t','!'};
    const Bytes key = randomBytes(KEY_SIZE);
    const CipherPackage original = encryptWithFreshNonce(plaintext, key);
    Bytes recovered;

    auto tampered = original;
    tampered.ciphertext[0] ^= 0x01;
    allPassed &= reportTest("Ciphertext tampering", !decryptBytes(tampered, key, recovered),
                            "a one-bit ciphertext change was rejected by GCM authentication");

    tampered = original;
    tampered.tag[0] ^= 0x01;
    allPassed &= reportTest("Tag modification", !decryptBytes(tampered, key, recovered),
                            "a one-bit authentication-tag change was rejected");

    Bytes wrongKey = randomBytes(KEY_SIZE);
    allPassed &= reportTest("Wrong-key attack", !decryptBytes(original, wrongKey, recovered),
                            "a different 256-bit key could not authenticate the data");

    const Bytes message1{'A','t','t','a','c','k',' ','a','t',' ','d','a','w','n','!'};
    const Bytes message2{'D','e','f','e','n','d',' ','a','t',' ','d','u','s','k','!'};
    std::array<unsigned char, NONCE_SIZE> reusedNonce{};
    const Bytes nonceSeed = randomBytes(NONCE_SIZE);
    std::copy(nonceSeed.begin(), nonceSeed.end(), reusedNonce.begin());
    const auto first = encryptBytes(message1, key, reusedNonce);
    const auto second = encryptBytes(message2, key, reusedNonce);
    bool xorLeak = first.ciphertext.size() == second.ciphertext.size();
    for (std::size_t i = 0; xorLeak && i < message1.size(); ++i) {
        xorLeak = static_cast<unsigned char>(first.ciphertext[i] ^ second.ciphertext[i]) ==
                  static_cast<unsigned char>(message1[i] ^ message2[i]);
    }
    allPassed &= reportTest("Nonce reuse analysis", xorLeak,
                            "reusing key+nonce made C1 XOR C2 equal P1 XOR P2, leaking plaintext relationships; "
                            "GCM nonce reuse also exposes authentication relationships that can enable forgeries");

    const auto freshPackage = encryptWithFreshNonce(plaintext, key);
    const bool authenticated = decryptBytes(freshPackage, key, recovered);
    allPassed &= reportTest("Correctness verification", authenticated && recovered == plaintext,
                            "fresh-nonce encryption decrypted to bytes identical to the original");

    std::cout << (allPassed ? "ALL TESTS PASSED\n" : "ONE OR MORE TESTS FAILED\n");
    return allPassed ? 0 : 1;
}

void printUsage(const char* program) {
    std::cout << "Usage:\n"
              << "  " << program << " encrypt input.txt encrypted.bin key.bin\n"
              << "  " << program << " decrypt encrypted.bin key.bin output.txt\n"
              << "  " << program << " test\n";
}
}  // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc == 5 && std::string(argv[1]) == "encrypt") {
            encryptCommand(argv[2], argv[3], argv[4]);
            return 0;
        }
        if (argc == 5 && std::string(argv[1]) == "decrypt") {
            decryptCommand(argv[2], argv[3], argv[4]);
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "test") return testCommand();
        printUsage(argv[0]);
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
