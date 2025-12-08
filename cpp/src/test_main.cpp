// src/test_main.cpp
#include <array>
#include <cstdint>
#include <iostream>

#include "mlkem_512_c_api.hpp"

int main() {
    const std::size_t pk_len = mlkem_512_pkey_len();
    const std::size_t sk_len = mlkem_512_skey_len();
    const std::size_t ct_len = mlkem_512_cipher_len();
    const std::size_t ss_len = mlkem_512_shared_secret_len();

    std::cout << "ML-KEM-512 sizes:\n"
              << "  public key:  " << pk_len << "\n"
              << "  secret key:  " << sk_len << "\n"
              << "  ciphertext:  " << ct_len << "\n"
              << "  shared sec.: " << ss_len << "\n";

    std::array<std::uint8_t, 800>  pk{};
    std::array<std::uint8_t, 1632> sk{};
    std::array<std::uint8_t, 768>  ct{};
    std::array<std::uint8_t, 32>   ss1{};
    std::array<std::uint8_t, 32>   ss2{};

    if (pk_len != pk.size() || sk_len != sk.size() ||
        ct_len != ct.size() || ss_len != ss1.size()) {
        std::cerr << "Size mismatch between header and hardcoded arrays.\n";
        return 1;
    }

    int rc = mlkem_512_keygen(pk.data(), sk.data());
    if (rc != 0) {
        std::cerr << "Keygen failed.\n";
        return 1;
    }

    rc = mlkem_512_encaps(pk.data(), ct.data(), ss1.data());
    if (rc != 0) {
        std::cerr << "Encaps failed (malformed pk?).\n";
        return 1;
    }

    rc = mlkem_512_decaps(sk.data(), ct.data(), ss2.data());
    if (rc != 0) {
        std::cerr << "Decaps failed.\n";
        return 1;
    }

    bool equal = true;
    for (std::size_t i = 0; i < ss1.size(); ++i) {
        if (ss1[i] != ss2[i]) {
            equal = false;
            break;
        }
    }

    if (!equal) {
        std::cerr << "Shared secrets don't match.\n";
        return 1;
    }

    std::cout << "ML-KEM-512 test OK: shared secrets match.\n";
    return 0;
}
