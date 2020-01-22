#ifndef ENACL_AEAD_H
#define ENACL_AEAD_H

#include <erl_nif.h>

/* AEAD ChaCha20 Poly1305 */
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_KEYBYTES(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_NPUBBYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_ABYTES(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX(
    ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_encrypt(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_decrypt(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]);

/* AEAD XChaCha20 Poly1305 */
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_KEYBYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_ABYTES(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX(
    ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_encrypt(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_decrypt(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]);

#endif
