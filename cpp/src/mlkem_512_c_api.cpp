#include "mlkem_512_c_api.hpp"
#include "mlkem_512.hpp"

// RandomSHAKE CSPRNG
#include "randomshake/randomshake.hpp"

#include <array>
#include <span>
#include <cstdint>

using ml_kem_512::PKEY_BYTE_LEN;
using ml_kem_512::SKEY_BYTE_LEN;
using ml_kem_512::CIPHER_TEXT_BYTE_LEN;
using ml_kem_512::SHARED_SECRET_BYTE_LEN;
using ml_kem_512::SEED_D_BYTE_LEN;
using ml_kem_512::SEED_Z_BYTE_LEN;
using ml_kem_512::SEED_M_BYTE_LEN;

// -----------------------------------------------------------------------------
// Single global CSPRNG instance (RandomSHAKE)
// -----------------------------------------------------------------------------
namespace
{
    // Default template params of randomshake_t<> are fine for us.
    static randomshake::randomshake_t<> g_csprng;

    inline void csprng_fill(std::span<std::uint8_t> out)
    {
        // Typical RandomSHAKE usage is generate(container/span)
        // If your header expects a different signature
        // (e.g. generate(ptr, len)), adapt this ONE place.
        g_csprng.generate(out);
    }
} // anonymous namespace

extern "C" {

// -----------------------------------------------------------------------------
// Size query helpers
// -----------------------------------------------------------------------------
std::size_t mlkem_512_pkey_len() {
    return PKEY_BYTE_LEN;
}

std::size_t mlkem_512_skey_len() {
    return SKEY_BYTE_LEN;
}

std::size_t mlkem_512_cipher_len() {
    return CIPHER_TEXT_BYTE_LEN;
}

std::size_t mlkem_512_shared_secret_len() {
    return SHARED_SECRET_BYTE_LEN;
}

// -----------------------------------------------------------------------------
// Key generation: produces public & secret key
// -----------------------------------------------------------------------------
int mlkem_512_keygen(std::uint8_t* pk_out, std::uint8_t* sk_out) {
    if (!pk_out || !sk_out) {
        return -1;
    }

    std::array<std::uint8_t, SEED_D_BYTE_LEN> d{};
    std::array<std::uint8_t, SEED_Z_BYTE_LEN> z{};

    // Fill seeds using RandomSHAKE CSPRNG
    csprng_fill(std::span<std::uint8_t, SEED_D_BYTE_LEN>(d.data(), d.size()));
    csprng_fill(std::span<std::uint8_t, SEED_Z_BYTE_LEN>(z.data(), z.size()));

    std::span<const std::uint8_t, SEED_D_BYTE_LEN> d_span(d.data(), d.size());
    std::span<const std::uint8_t, SEED_Z_BYTE_LEN> z_span(z.data(), z.size());
    std::span<std::uint8_t, PKEY_BYTE_LEN> pk_span(pk_out, PKEY_BYTE_LEN);
    std::span<std::uint8_t, SKEY_BYTE_LEN> sk_span(sk_out, SKEY_BYTE_LEN);

    ml_kem_512::keygen(d_span, z_span, pk_span, sk_span);
    return 0;
}

// -----------------------------------------------------------------------------
// Encapsulation: pk_in → ct_out, ss_out
// -----------------------------------------------------------------------------
int mlkem_512_encaps(const std::uint8_t* pk_in,
                     std::uint8_t* ct_out,
                     std::uint8_t* ss_out) {
    if (!pk_in || !ct_out || !ss_out) {
        return -1;
    }

    std::array<std::uint8_t, SEED_M_BYTE_LEN> m{};
    csprng_fill(std::span<std::uint8_t, SEED_M_BYTE_LEN>(m.data(), m.size()));

    std::span<const std::uint8_t, SEED_M_BYTE_LEN> m_span(m.data(), m.size());
    std::span<const std::uint8_t, PKEY_BYTE_LEN> pk_span(pk_in, PKEY_BYTE_LEN);
    std::span<std::uint8_t, CIPHER_TEXT_BYTE_LEN> ct_span(ct_out, CIPHER_TEXT_BYTE_LEN);
    std::span<std::uint8_t, SHARED_SECRET_BYTE_LEN> ss_span(ss_out, SHARED_SECRET_BYTE_LEN);

    bool ok = ml_kem_512::encapsulate(m_span, pk_span, ct_span, ss_span);
    return ok ? 0 : -1;
}

// -----------------------------------------------------------------------------
// Decapsulation: sk_in + ct_in → ss_out
// -----------------------------------------------------------------------------
int mlkem_512_decaps(const std::uint8_t* sk_in,
                     const std::uint8_t* ct_in,
                     std::uint8_t* ss_out) {
    if (!sk_in || !ct_in || !ss_out) {
        return -1;
    }

    std::span<const std::uint8_t, SKEY_BYTE_LEN> sk_span(sk_in, SKEY_BYTE_LEN);
    std::span<const std::uint8_t, CIPHER_TEXT_BYTE_LEN> ct_span(ct_in, CIPHER_TEXT_BYTE_LEN);
    std::span<std::uint8_t, SHARED_SECRET_BYTE_LEN> ss_span(ss_out, SHARED_SECRET_BYTE_LEN);

    ml_kem_512::decapsulate(sk_span, ct_span, ss_span);
    return 0;
}

} // extern "C"
