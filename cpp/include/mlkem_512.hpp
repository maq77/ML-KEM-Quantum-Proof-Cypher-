#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "ml_kem/internals/ml_kem.hpp"
#include "ml_kem/internals/utility/utils.hpp"
using namespace std;

namespace ml_kem_512 {

// ---------------------------------------------------------------------
// Parameters for ML-KEM-512  (FIPS 203, Table 2, row 1)
// ---------------------------------------------------------------------

inline constexpr size_t k  = 2;
inline constexpr size_t η1 = 3;
inline constexpr size_t η2 = 2;
inline constexpr size_t du = 10;
inline constexpr size_t dv = 4;

// Seed sizes
inline constexpr size_t SEED_D_BYTE_LEN = 32; // for K-PKE keygen
inline constexpr size_t SEED_Z_BYTE_LEN = 32; // for KEM keygen
inline constexpr size_t SEED_M_BYTE_LEN = 32; // for encapsulation

// Public / Secret key sizes
inline constexpr size_t PKEY_BYTE_LEN =
  ml_kem_utils::get_kem_public_key_len(k);

inline constexpr size_t SKEY_BYTE_LEN =
  ml_kem_utils::get_kem_secret_key_len(k);

// Ciphertext + Shared secret sizes
inline constexpr size_t CIPHER_TEXT_BYTE_LEN =
  ml_kem_utils::get_kem_cipher_text_len(k, du, dv);

inline constexpr size_t SHARED_SECRET_BYTE_LEN = 32;

// ---------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------
constexpr void
keygen(span<const uint8_t, SEED_D_BYTE_LEN> d,
       span<const uint8_t, SEED_Z_BYTE_LEN> z,
       span<uint8_t, PKEY_BYTE_LEN>         pubkey,
       span<uint8_t, SKEY_BYTE_LEN>         seckey)
{
  ml_kem::keygen<k, η1>(d, z, pubkey, seckey);
}

// ---------------------------------------------------------------------
// Encapsulation
// ---------------------------------------------------------------------
[[nodiscard("If public key is malformed, encapsulation fails")]]
constexpr bool
encapsulate(span<const uint8_t, SEED_M_BYTE_LEN> m,
            span<const uint8_t, PKEY_BYTE_LEN>   pubkey,
            span<uint8_t, CIPHER_TEXT_BYTE_LEN>  cipher,
            span<uint8_t, SHARED_SECRET_BYTE_LEN> shared_secret)
{
  return ml_kem::encapsulate<k, η1, η2, du, dv>(m, pubkey, cipher, shared_secret);
}

// ---------------------------------------------------------------------
// Decapsulation
// ---------------------------------------------------------------------
constexpr void
decapsulate(span<const uint8_t, SKEY_BYTE_LEN>   seckey,
            span<const uint8_t, CIPHER_TEXT_BYTE_LEN> cipher,
            span<uint8_t, SHARED_SECRET_BYTE_LEN> shared_secret)
{
  ml_kem::decapsulate<k, η1, η2, du, dv>(seckey, cipher, shared_secret);
}

} 
