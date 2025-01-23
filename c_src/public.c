#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "public.h"

/* Public-key cryptography */
ERL_NIF_TERM enacl_crypto_box_NONCEBYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_NONCEBYTES);
}

ERL_NIF_TERM enacl_crypto_box_ZEROBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_ZEROBYTES);
}

ERL_NIF_TERM enacl_crypto_box_BOXZEROBYTES(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_BOXZEROBYTES);
}

ERL_NIF_TERM enacl_crypto_box_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_PUBLICKEYBYTES);
}

ERL_NIF_TERM enacl_crypto_box_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_SECRETKEYBYTES);
}

ERL_NIF_TERM enacl_crypto_box_BEFORENMBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_BEFORENMBYTES);
}

ERL_NIF_TERM enacl_crypto_box_SEALBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_SEALBYTES);
}

ERL_NIF_TERM enacl_crypto_box_keypair(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_box_PUBLICKEYBYTES, &pk)) {
    return enacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_box_SECRETKEYBYTES, &sk)) {
    enif_release_binary(&pk);
    return enacl_error_tuple(env, "alloc_failed");
  }

  crypto_box_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

ERL_NIF_TERM enacl_crypto_box(ErlNifEnv *env, int argc,
                              ERL_NIF_TERM const argv[]) {
  ErlNifBinary padded_msg, nonce, pk, sk, result;
  ERL_NIF_TERM ret;

  if (argc != 4)
    goto bad_arg;
  if (!enif_inspect_iolist_as_binary(env, argv[0], &padded_msg))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &nonce))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[2], &pk))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[3], &sk))
    goto bad_arg;

  if (nonce.size != crypto_box_NONCEBYTES)
    goto bad_arg;
  if (pk.size != crypto_box_PUBLICKEYBYTES)
    goto bad_arg;
  if (sk.size != crypto_box_SECRETKEYBYTES)
    goto bad_arg;
  if (padded_msg.size < crypto_box_ZEROBYTES)
    goto bad_arg;

  if (!enif_alloc_binary(padded_msg.size, &result)) {
    goto err;
  }

  if (0 != crypto_box(result.data, padded_msg.data, padded_msg.size, nonce.data,
                      pk.data, sk.data)) {
    goto release;
  }

  ret = enif_make_sub_binary(env, enif_make_binary(env, &result),
                             crypto_box_BOXZEROBYTES,
                             padded_msg.size - crypto_box_BOXZEROBYTES);

  goto done;

bad_arg:
  return enif_make_badarg(env);
release:
  enif_release_binary(&result);
err:
  ret = enacl_internal_error(env);
done:
  return ret;
}

ERL_NIF_TERM enacl_crypto_box_open(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]) {
  ErlNifBinary padded_ciphertext, nonce, pk, sk, result;

  if ((argc != 4) ||
      (!enif_inspect_iolist_as_binary(env, argv[0], &padded_ciphertext)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &pk)) ||
      (!enif_inspect_binary(env, argv[3], &sk))) {
    return enif_make_badarg(env);
  }

  if ((nonce.size != crypto_box_NONCEBYTES) ||
      (pk.size != crypto_box_PUBLICKEYBYTES) ||
      (sk.size != crypto_box_SECRETKEYBYTES) ||
      (padded_ciphertext.size < crypto_box_BOXZEROBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(padded_ciphertext.size, &result)) {
    return enacl_internal_error(env);
  }

  if (0 != crypto_box_open(result.data, padded_ciphertext.data,
                           padded_ciphertext.size, nonce.data, pk.data,
                           sk.data)) {
    enif_release_binary(&result);
    return enacl_error_tuple(env, "failed_verification");
  }

  ERL_NIF_TERM ret_ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret_bin = enif_make_sub_binary(
      env, enif_make_binary(env, &result), crypto_box_ZEROBYTES,
      padded_ciphertext.size - crypto_box_ZEROBYTES);

  return enif_make_tuple2(env, ret_ok, ret_bin);
}

/* Precomputed crypto boxes */

ERL_NIF_TERM enacl_crypto_box_beforenm(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]) {
  ErlNifBinary k, pk, sk;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &pk)) ||
      (!enif_inspect_binary(env, argv[1], &sk)) ||
      (pk.size != crypto_box_PUBLICKEYBYTES) ||
      (sk.size != crypto_box_SECRETKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_box_BEFORENMBYTES, &k)) {
    goto err;
  }

  if (0 != crypto_box_beforenm(k.data, pk.data, sk.data)) {
    // error
    enif_release_binary(&k);
    goto err;
  }

  return enif_make_binary(env, &k);
err:
  return enacl_internal_error(env);
}

ERL_NIF_TERM enacl_crypto_box_afternm(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]) {
  ErlNifBinary result, m, nonce, k;

  if ((argc != 3) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &k)) ||
      (m.size < crypto_box_ZEROBYTES) ||
      (nonce.size != crypto_box_NONCEBYTES) ||
      (k.size != crypto_box_BEFORENMBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(m.size, &result)) {
    return enacl_internal_error(env);
  }

  crypto_box_afternm(result.data, m.data, m.size, nonce.data, k.data);

  return enif_make_sub_binary(env, enif_make_binary(env, &result),
                              crypto_box_BOXZEROBYTES,
                              m.size - crypto_box_BOXZEROBYTES);
}

ERL_NIF_TERM enacl_crypto_box_open_afternm(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  ErlNifBinary result, m, nonce, k;

  if ((argc != 3) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &k)) ||
      (m.size < crypto_box_BOXZEROBYTES) ||
      (nonce.size != crypto_box_NONCEBYTES) ||
      (k.size != crypto_box_BEFORENMBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(m.size, &result)) {
    return enacl_internal_error(env);
  }

  if (0 != crypto_box_open_afternm(result.data, m.data, m.size, nonce.data,
                                   k.data)) {
    enif_release_binary(&result);
    return enacl_error_tuple(env, "failed_verification");
  }

  ERL_NIF_TERM ret_ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret_bin =
      enif_make_sub_binary(env, enif_make_binary(env, &result),
                           crypto_box_ZEROBYTES, m.size - crypto_box_ZEROBYTES);
  return enif_make_tuple2(env, ret_ok, ret_bin);
}

/* Sealed box functions */

ERL_NIF_TERM enacl_crypto_box_seal(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, msg, ciphertext;

  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &msg)) ||
      (!enif_inspect_binary(env, argv[1], &key))) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(msg.size + crypto_box_SEALBYTES, &ciphertext)) {
    return enacl_internal_error(env);
  }

  crypto_box_seal(ciphertext.data, msg.data, msg.size, key.data);

  return enif_make_binary(env, &ciphertext);
}

ERL_NIF_TERM enacl_crypto_box_seal_open(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk, ciphertext, msg;

  if ((argc != 3) ||
      (!enif_inspect_iolist_as_binary(env, argv[0], &ciphertext)) ||
      (!enif_inspect_binary(env, argv[1], &pk)) ||
      (!enif_inspect_binary(env, argv[2], &sk))) {
    return enif_make_badarg(env);
  }

  if (ciphertext.size < crypto_box_SEALBYTES) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(ciphertext.size - crypto_box_SEALBYTES, &msg)) {
    return enacl_internal_error(env);
  }

  if (crypto_box_seal_open(msg.data, ciphertext.data, ciphertext.size, pk.data,
                           sk.data) != 0) {
    enif_release_binary(&msg);
    return enacl_error_tuple(env, "failed_verification");
  }

  ERL_NIF_TERM ret_ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret_bin = enif_make_binary(env, &msg);

  return enif_make_tuple2(env, ret_ok, ret_bin);
}
