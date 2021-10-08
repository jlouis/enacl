#ifndef ENACL_PUBLIC_H
#define ENACL_PUBLIC_H

ERL_NIF_TERM enacl_crypto_box_NONCEBYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_ZEROBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_BOXZEROBYTES(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_BEFORENMBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_keypair(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box(ErlNifEnv *env, int argc,
                              ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_open(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_beforenm(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_afternm(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_open_afternm(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_SEALBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_seal(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_box_seal_open(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]);

#endif