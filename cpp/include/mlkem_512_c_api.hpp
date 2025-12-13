#pragma once
#include <cstddef>
#include <cstdint>

using namespace std;
extern "C" {

size_t mlkem_512_pkey_len();
size_t mlkem_512_skey_len();
size_t mlkem_512_cipher_len();
size_t mlkem_512_shared_secret_len();

// Keygen: makes public & secret key
int mlkem_512_keygen(uint8_t* pk_out, uint8_t* sk_out);

// pk_in → ct_out, ss_out
// pk_in:  public key buffer
// ct_out: cipher text buffer
// ss_out: shared secret buffer
// returns 0 on success, -1 if malformed public key
int mlkem_512_encaps(const uint8_t* pk_in,
                     uint8_t* ct_out,
                     uint8_t* ss_out);

// Decapsulate: sk_in + ct_in → ss_out
// returns 0 on success
int mlkem_512_decaps(const uint8_t* sk_in,
                     const uint8_t* ct_in,
                     uint8_t* ss_out);

} 
