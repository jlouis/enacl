#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "randombytes.h"

ERL_NIF_TERM enif_randombytes(ErlNifEnv *env, int argc,
                              ERL_NIF_TERM const argv[]) {
  unsigned req_size;
  ErlNifBinary result;

  if ((argc != 1) || (!enif_get_uint(env, argv[0], &req_size))) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(req_size, &result)) {
    return enacl_internal_error(env);
  }

  randombytes(result.data, result.size);

  return enif_make_binary(env, &result);
}

ERL_NIF_TERM enif_randombytes_uint32(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  ErlNifUInt64 result;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  result = randombytes_random();
  return enif_make_uint64(env, result);
}

ERL_NIF_TERM enif_randombytes_uniform(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]) {
  unsigned upper_bound;
  ErlNifUInt64 result;

  if ((argc != 1) || (!enif_get_uint(env, argv[0], &upper_bound))) {
    return enif_make_badarg(env);
  }

  result = randombytes_uniform(upper_bound);
  return enif_make_uint64(env, result);
}
