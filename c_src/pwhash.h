#ifndef ENACL_PWHASH_H
#define ENACL_PWHASH_H

#include <erl_nif.h>

ERL_NIF_TERM enacl_crypto_pwhash_SALTBYTES(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_pwhash(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_pwhash_str(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_pwhash_str_verify(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

#endif
