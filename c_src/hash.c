#include "erl_nif.h"

#include <sodium.h>

#include "hash.h"

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
  ret = nacl_error_tuple(env, "alloc_failed");
done:
  return ret;
}
