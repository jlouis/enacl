#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "secret.h"

/* Secret key cryptography */

ERL_NIF_TERM
enacl_crypto_secretbox_NONCEBYTES(ErlNifEnv *env, int argc,
                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_secretbox_NONCEBYTES);
}

ERL_NIF_TERM enacl_crypto_secretbox_KEYBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_secretbox_KEYBYTES);
}

ERL_NIF_TERM
enacl_crypto_secretbox_ZEROBYTES(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_secretbox_ZEROBYTES);
}

ERL_NIF_TERM
enacl_crypto_secretbox_BOXZEROBYTES(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_secretbox_BOXZEROBYTES);
}

ERL_NIF_TERM
enacl_crypto_stream_chacha20_KEYBYTES(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_stream_chacha20_KEYBYTES);
}

ERL_NIF_TERM
enacl_crypto_stream_chacha20_NONCEBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_stream_chacha20_NONCEBYTES);
}

ERL_NIF_TERM enacl_crypto_stream_KEYBYTES(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_stream_KEYBYTES);
}

ERL_NIF_TERM enacl_crypto_stream_NONCEBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_stream_NONCEBYTES);
}

ERL_NIF_TERM enacl_crypto_auth_BYTES(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_auth_BYTES);
}

ERL_NIF_TERM enacl_crypto_auth_KEYBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_auth_KEYBYTES);
}

ERL_NIF_TERM enacl_crypto_onetimeauth_BYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_onetimeauth_BYTES);
}

ERL_NIF_TERM
enacl_crypto_onetimeauth_KEYBYTES(ErlNifEnv *env, int argc,
                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_onetimeauth_KEYBYTES);
}

ERL_NIF_TERM enacl_crypto_secretbox(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, nonce, padded_msg, padded_ciphertext;

  if ((argc != 3) ||
      (!enif_inspect_iolist_as_binary(env, argv[0], &padded_msg)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &key))) {
    return enif_make_badarg(env);
  }

  if ((key.size != crypto_secretbox_KEYBYTES) ||
      (nonce.size != crypto_secretbox_NONCEBYTES) ||
      (padded_msg.size < crypto_secretbox_ZEROBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(padded_msg.size, &padded_ciphertext)) {
    return enacl_internal_error(env);
  }

  crypto_secretbox(padded_ciphertext.data, padded_msg.data, padded_msg.size,
                   nonce.data, key.data);

  return enif_make_sub_binary(env, enif_make_binary(env, &padded_ciphertext),
                              crypto_secretbox_BOXZEROBYTES,
                              padded_msg.size - crypto_secretbox_BOXZEROBYTES);
}

ERL_NIF_TERM enacl_crypto_secretbox_open(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, nonce, padded_ciphertext, padded_msg;

  if ((argc != 3) ||
      (!enif_inspect_iolist_as_binary(env, argv[0], &padded_ciphertext)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &key))) {
    return enif_make_badarg(env);
  }

  if ((key.size != crypto_secretbox_KEYBYTES) ||
      (nonce.size != crypto_secretbox_NONCEBYTES) ||
      (padded_ciphertext.size < crypto_secretbox_BOXZEROBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(padded_ciphertext.size, &padded_msg)) {
    return enacl_internal_error(env);
  }

  if (crypto_secretbox_open(padded_msg.data, padded_ciphertext.data,
                            padded_ciphertext.size, nonce.data,
                            key.data) != 0) {
    enif_release_binary(&padded_msg);
    return enacl_error_tuple(env, "failed_verification");
  }

  ERL_NIF_TERM ret_ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret_bin = enif_make_sub_binary(
      env, enif_make_binary(env, &padded_msg), crypto_secretbox_ZEROBYTES,
      padded_ciphertext.size - crypto_secretbox_ZEROBYTES);
  return enif_make_tuple2(env, ret_ok, ret_bin);
}

ERL_NIF_TERM enacl_crypto_secretbox_easy(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, nonce, msg, cipherbox;

  if ((argc != 3) ||
      (!enif_inspect_iolist_as_binary(env, argv[0], &msg)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &key))) {
    return enif_make_badarg(env);
  }

  if ((key.size != crypto_secretbox_KEYBYTES) ||
      (nonce.size != crypto_secretbox_NONCEBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(msg.size + crypto_secretbox_MACBYTES, &cipherbox)) {
    return enacl_internal_error(env);
  }

  crypto_secretbox_easy(cipherbox.data, msg.data, msg.size,
                        nonce.data, key.data);

  return enif_make_binary(env, &cipherbox);
}

ERL_NIF_TERM enacl_crypto_secretbox_open_easy(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, nonce, cipherbox, msg;

  if ((argc != 3) ||
      (!enif_inspect_iolist_as_binary(env, argv[0], &cipherbox)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &key))) {
    return enif_make_badarg(env);
  }

  if ((key.size != crypto_secretbox_KEYBYTES) ||
      (nonce.size != crypto_secretbox_NONCEBYTES) ||
      (cipherbox.size < crypto_secretbox_MACBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(cipherbox.size - crypto_secretbox_MACBYTES, &msg)) {
    return enacl_internal_error(env);
  }

  if (crypto_secretbox_open_easy(msg.data, cipherbox.data, cipherbox.size,
                                 nonce.data, key.data) != 0) {
    enif_release_binary(&msg);
    return enacl_error_tuple(env, "failed_verification");
  }

  ERL_NIF_TERM ret_ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret_bin = enif_make_binary(env, &msg);
  return enif_make_tuple2(env, ret_ok, ret_bin);
}

ERL_NIF_TERM enacl_crypto_stream_chacha20(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  ErlNifBinary c, n, k;
  ErlNifUInt64 clen;

  if ((argc != 3) || (!enif_get_uint64(env, argv[0], &clen)) ||
      (!enif_inspect_binary(env, argv[1], &n)) ||
      (!enif_inspect_binary(env, argv[2], &k))) {
    return enif_make_badarg(env);
  }

  if ((k.size != crypto_stream_chacha20_KEYBYTES) ||
      (n.size != crypto_stream_chacha20_NONCEBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(clen, &c)) {
    return enacl_internal_error(env);
  }

  crypto_stream_chacha20(c.data, c.size, n.data, k.data);

  return enif_make_binary(env, &c);
}

ERL_NIF_TERM
enacl_crypto_stream_chacha20_xor(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]) {
  ErlNifBinary c, m, n, k;

  if ((argc != 3) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &n)) ||
      (!enif_inspect_binary(env, argv[2], &k))) {
    return enif_make_badarg(env);
  }

  if ((k.size != crypto_stream_chacha20_KEYBYTES) ||
      (n.size != crypto_stream_chacha20_NONCEBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(m.size, &c)) {
    return enacl_internal_error(env);
  }

  crypto_stream_chacha20_xor(c.data, m.data, m.size, n.data, k.data);

  return enif_make_binary(env, &c);
}

ERL_NIF_TERM enacl_crypto_stream(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]) {
  ErlNifBinary c, n, k;
  ErlNifUInt64 clen;

  if ((argc != 3) || (!enif_get_uint64(env, argv[0], &clen)) ||
      (!enif_inspect_binary(env, argv[1], &n)) ||
      (!enif_inspect_binary(env, argv[2], &k))) {
    return enif_make_badarg(env);
  }

  if ((k.size != crypto_stream_KEYBYTES) ||
      (n.size != crypto_stream_NONCEBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(clen, &c)) {
    return enacl_internal_error(env);
  }

  crypto_stream(c.data, c.size, n.data, k.data);

  return enif_make_binary(env, &c);
}

ERL_NIF_TERM enacl_crypto_stream_xor(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  ErlNifBinary c, m, n, k;

  if ((argc != 3) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &n)) ||
      (!enif_inspect_binary(env, argv[2], &k))) {
    return enif_make_badarg(env);
  }

  if ((k.size != crypto_stream_KEYBYTES) ||
      (n.size != crypto_stream_NONCEBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(m.size, &c)) {
    return enacl_internal_error(env);
  }

  crypto_stream_xor(c.data, m.data, m.size, n.data, k.data);

  return enif_make_binary(env, &c);
}

ERL_NIF_TERM enacl_crypto_auth(ErlNifEnv *env, int argc,
                               ERL_NIF_TERM const argv[]) {
  ErlNifBinary a, m, k;

  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &k))) {
    return enif_make_badarg(env);
  }

  if (k.size != crypto_auth_KEYBYTES) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_auth_BYTES, &a)) {
    return enacl_internal_error(env);
  }

  crypto_auth(a.data, m.data, m.size, k.data);

  return enif_make_binary(env, &a);
}

ERL_NIF_TERM enacl_crypto_auth_verify(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]) {
  ErlNifBinary a, m, k;

  if ((argc != 3) || (!enif_inspect_binary(env, argv[0], &a)) ||
      (!enif_inspect_iolist_as_binary(env, argv[1], &m)) ||
      (!enif_inspect_binary(env, argv[2], &k))) {
    return enif_make_badarg(env);
  }

  if ((k.size != crypto_auth_KEYBYTES) || (a.size != crypto_auth_BYTES)) {
    return enif_make_badarg(env);
  }

  if (0 == crypto_auth_verify(a.data, m.data, m.size, k.data)) {
    return enif_make_atom(env, "true");
  } else {
    return enif_make_atom(env, "false");
  }
}

ERL_NIF_TERM enacl_crypto_onetimeauth(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]) {
  ErlNifBinary a, m, k;

  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &k))) {
    return enif_make_badarg(env);
  }

  if (k.size != crypto_onetimeauth_KEYBYTES) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_onetimeauth_BYTES, &a)) {
    return enacl_internal_error(env);
  }

  crypto_onetimeauth(a.data, m.data, m.size, k.data);

  return enif_make_binary(env, &a);
}

ERL_NIF_TERM enacl_crypto_onetimeauth_verify(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  ErlNifBinary a, m, k;

  if ((argc != 3) || (!enif_inspect_binary(env, argv[0], &a)) ||
      (!enif_inspect_iolist_as_binary(env, argv[1], &m)) ||
      (!enif_inspect_binary(env, argv[2], &k))) {
    return enif_make_badarg(env);
  }

  if ((k.size != crypto_onetimeauth_KEYBYTES) ||
      (a.size != crypto_onetimeauth_BYTES)) {
    return enif_make_badarg(env);
  }

  if (0 == crypto_onetimeauth_verify(a.data, m.data, m.size, k.data)) {
    return enif_make_atom(env, "true");
  } else {
    return enif_make_atom(env, "false");
  }
}
