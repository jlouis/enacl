#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "kdf.h"


ERL_NIF_TERM enacl_crypto_kdf_KEYBYTES(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_kdf_KEYBYTES);
}

ERL_NIF_TERM enacl_crypto_kdf_CONTEXTBYTES(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_kdf_CONTEXTBYTES);
}


ERL_NIF_TERM enacl_crypto_kdf_derive_from_key(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  ErlNifBinary m, c, r;
  ErlNifUInt64 id;

  // Validate the arguments
  if ((argc != 3) ||
      (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &c)) ||
      (!enif_get_uint64(env, argv[2], &id))) {
    return enif_make_badarg(env);
  }

  // Check Master Key length
  if (m.size != crypto_kdf_KEYBYTES) {
    return enif_make_badarg(env);
  }

  // Check Context Key length
  if (c.size != crypto_kdf_CONTEXTBYTES) {
    return enif_make_badarg(env);
  }

  // Allocate memory for return binary
  if (!enif_alloc_binary(crypto_kdf_KEYBYTES, &r)) {
    return enacl_internal_error(env);
  }

  if (crypto_kdf_derive_from_key(r.data, r.size,
                    id,
                    (const char *)c.data,
                    m.data) != 0) {
    /* out of memory */
    enif_release_binary(&r);
    return enacl_internal_error(env);
  }

  return enif_make_binary(env, &r);
}

