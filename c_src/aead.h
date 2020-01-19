#ifndef ENACL_AEAD_H
#define ENACL_AEAD_H

#include "erl_nif.h"

/* AEAD ChaCha20 Poly1305 */
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_KEYBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_NPUBBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ABYTES(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX(ErlNifEnv *env, int argc,
                                                    ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_encrypt(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_decrypt(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]);

/* AEAD XChaCha20 Poly1305 */
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_KEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_NPUBBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ABYTES(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_MESSAGEBYTES_MAX(ErlNifEnv *env, int argc,
                                                     ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_encrypt(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_decrypt(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

#endif
