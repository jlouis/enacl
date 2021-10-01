#ifndef ENACL_EXT_H
#define ENACL_EXT_H

#include <erl_nif.h>

ERL_NIF_TERM enif_scramble_block_16(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]);

#endif
