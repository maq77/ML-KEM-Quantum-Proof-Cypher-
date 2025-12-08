#pragma once
#include <cstddef>
#include <cstdint>

extern "C" {

// Query lengths so FFI (Python) can allocate buffers
std::size_t mlkem_512_pkey_len();
std::size_t mlkem_512_skey_len();
std::size_t mlkem_512_cipher_len();
std::size_t mlkem_512_shared_secret_len();

// Generate ML-KEM-512 keypair
// pk_out: buffer with size mlkem_512_pkey_len()
// sk_out: buffer with size mlkem_512_skey_len()
// returns 0 on success
int mlkem_512_keygen(std::uint8_t* pk_out, std::uint8_t* sk_out);

// Encapsulate: pk_in → ct_out, ss_out
// pk_in:  public key buffer
// ct_out: cipher text buffer
// ss_out: shared secret buffer (32 bytes)
// returns 0 on success, -1 if malformed public key
int mlkem_512_encaps(const std::uint8_t* pk_in,
                     std::uint8_t* ct_out,
                     std::uint8_t* ss_out);

// Decapsulate: sk_in + ct_in → ss_out
// returns 0 on success
int mlkem_512_decaps(const std::uint8_t* sk_in,
                     const std::uint8_t* ct_in,
                     std::uint8_t* ss_out);

} // extern "C"
