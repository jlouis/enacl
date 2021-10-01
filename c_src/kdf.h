#ifndef ENACL_KDF_H
#define ENACL_KDF_H

#include <erl_nif.h>

ERL_NIF_TERM enacl_crypto_kdf_KEYBYTES(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_kdf_CONTEXTBYTES(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_kdf_derive_from_key(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]);

#endif
