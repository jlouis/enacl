#ifndef ENACL_RANDOMBYTES_H
#define ENACL_RANDOMBYTES_H

#include <erl_nif.h>

ERL_NIF_TERM enif_randombytes(ErlNifEnv *env, int argc,
                              ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enif_randombytes_uint32(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]);

ERL_NIF_TERM enif_randombytes_uniform(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]);

#endif