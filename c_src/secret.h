#ifndef ENACL_SECRET_H
#define ENACL_SECRET_H

ERL_NIF_TERM enacl_crypto_secretbox_NONCEBYTES(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_secretbox_KEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_secretbox_ZEROBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_secretbox_BOXZEROBYTES(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_stream_chacha20_KEYBYTES(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_stream_chacha20_NONCEBYTES(ErlNifEnv *env, int argc,
                                                     ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_stream_KEYBYTES(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_stream_NONCEBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_auth_BYTES(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_auth_KEYBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_onetimeauth_BYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_onetimeauth_KEYBYTES(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_secretbox(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_secretbox_open(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_secretbox_easy(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_secretbox_open_easy(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_stream_chacha20(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_stream_chacha20_xor(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_stream(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_stream_xor(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_auth(ErlNifEnv *env, int argc,
                               ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_auth_verify(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_onetimeauth(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enacl_crypto_onetimeauth_verify(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]);

#endif
