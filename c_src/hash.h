#ifndef ENACL_HASH_H
#define ENACL_HASH_H

#include <erl_nif.h>

ERL_NIF_TERM enacl_crypto_hash(ErlNifEnv *env, int argc,
                               const ERL_NIF_TERM argv[]);
#endif