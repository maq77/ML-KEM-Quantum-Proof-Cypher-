#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

// These headers must exist inside your copied ml_kem library.
#include "ml_kem/internals/ml_kem.hpp"
#include "ml_kem/internals/utility/utils.hpp"

namespace ml_kem_512 {

// ---------------------------------------------------------------------
// Parameters for ML-KEM-512  (FIPS 203, Table 2, row 1)
// ---------------------------------------------------------------------

inline constexpr std::size_t k  = 2;
inline constexpr std::size_t η1 = 3;
inline constexpr std::size_t η2 = 2;
inline constexpr std::size_t du = 10;
inline constexpr std::size_t dv = 4;

// Seed sizes
inline constexpr std::size_t SEED_D_BYTE_LEN = 32; // for K-PKE keygen
inline constexpr std::size_t SEED_Z_BYTE_LEN = 32; // for KEM keygen
inline constexpr std::size_t SEED_M_BYTE_LEN = 32; // for encapsulation

// Public / Secret key sizes
inline constexpr std::size_t PKEY_BYTE_LEN =
  ml_kem_utils::get_kem_public_key_len(k);

inline constexpr std::size_t SKEY_BYTE_LEN =
  ml_kem_utils::get_kem_secret_key_len(k);

// Ciphertext + Shared secret sizes
inline constexpr std::size_t CIPHER_TEXT_BYTE_LEN =
  ml_kem_utils::get_kem_cipher_text_len(k, du, dv);

inline constexpr std::size_t SHARED_SECRET_BYTE_LEN = 32;

// ---------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------
constexpr void
keygen(std::span<const std::uint8_t, SEED_D_BYTE_LEN> d,
       std::span<const std::uint8_t, SEED_Z_BYTE_LEN> z,
       std::span<std::uint8_t, PKEY_BYTE_LEN>         pubkey,
       std::span<std::uint8_t, SKEY_BYTE_LEN>         seckey)
{
  ml_kem::keygen<k, η1>(d, z, pubkey, seckey);
}

// ---------------------------------------------------------------------
// Encapsulation
// ---------------------------------------------------------------------
[[nodiscard("If public key is malformed, encapsulation fails")]]
constexpr bool
encapsulate(std::span<const std::uint8_t, SEED_M_BYTE_LEN> m,
            std::span<const std::uint8_t, PKEY_BYTE_LEN>   pubkey,
            std::span<std::uint8_t, CIPHER_TEXT_BYTE_LEN>  cipher,
            std::span<std::uint8_t, SHARED_SECRET_BYTE_LEN> shared_secret)
{
  return ml_kem::encapsulate<k, η1, η2, du, dv>(m, pubkey, cipher, shared_secret);
}

// ---------------------------------------------------------------------
// Decapsulation
// ---------------------------------------------------------------------
constexpr void
decapsulate(std::span<const std::uint8_t, SKEY_BYTE_LEN>   seckey,
            std::span<const std::uint8_t, CIPHER_TEXT_BYTE_LEN> cipher,
            std::span<std::uint8_t, SHARED_SECRET_BYTE_LEN> shared_secret)
{
  ml_kem::decapsulate<k, η1, η2, du, dv>(seckey, cipher, shared_secret);
}

} // namespace ml_kem_512
