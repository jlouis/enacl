#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "hash.h"

ERL_NIF_TERM enacl_crypto_shorthash_BYTES(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_shorthash_BYTES);
}

ERL_NIF_TERM enacl_crypto_shorthash_KEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_shorthash_KEYBYTES);
}

ERL_NIF_TERM enacl_crypto_shorthash(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  ErlNifBinary a, m, k;

  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &k))) {
    return enif_make_badarg(env);
  }

  if (k.size != crypto_shorthash_KEYBYTES) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_shorthash_BYTES, &a)) {
    return enacl_internal_error(env);
  }

  crypto_shorthash(a.data, m.data, m.size, k.data);

  return enif_make_binary(env, &a);
}

ERL_NIF_TERM enacl_crypto_hash(ErlNifEnv *env, int argc,
                               ERL_NIF_TERM const argv[]) {
  ErlNifBinary input;
  ErlNifBinary result;
  ERL_NIF_TERM ret;

  if ((argc != 1) || (!enif_inspect_iolist_as_binary(env, argv[0], &input)))
    goto bad_arg;

  if (!enif_alloc_binary(crypto_hash_BYTES, &result))
    goto err;

  crypto_hash(result.data, input.data, input.size);
  ret = enif_make_binary(env, &result);
  goto done;

bad_arg:
  return enif_make_badarg(env);
err:
  ret = enacl_internal_error(env);
done:
  return ret;
}
