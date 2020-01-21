#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "pwhash.h"

static size_t enacl_pwhash_opslimit(ErlNifEnv *env, ERL_NIF_TERM arg) {
  ERL_NIF_TERM a;
  size_t r;

  if (enif_is_atom(env, arg)) {
    a = enif_make_atom(env, "interactive");
    if (enif_is_identical(a, arg)) {
      return crypto_pwhash_OPSLIMIT_INTERACTIVE;
    }

    a = enif_make_atom(env, "moderate");
    if (enif_is_identical(a, arg)) {
      return crypto_pwhash_OPSLIMIT_MODERATE;
    }

    a = enif_make_atom(env, "sensitive");
    if (enif_is_identical(a, arg)) {
      return crypto_pwhash_OPSLIMIT_SENSITIVE;
    }
  } else if (enif_get_ulong(env, arg, &r)) {
    return r;
  }

  return 0;
}

static size_t enacl_pwhash_memlimit(ErlNifEnv *env, ERL_NIF_TERM arg) {
  ERL_NIF_TERM a;
  size_t r;

  if (enif_is_atom(env, arg)) {
    a = enif_make_atom(env, "interactive");
    if (enif_is_identical(a, arg)) {
      return crypto_pwhash_MEMLIMIT_INTERACTIVE;
    }

    a = enif_make_atom(env, "moderate");
    if (enif_is_identical(a, arg)) {
      return crypto_pwhash_MEMLIMIT_MODERATE;
    }

    a = enif_make_atom(env, "sensitive");
    if (enif_is_identical(a, arg)) {
      return crypto_pwhash_MEMLIMIT_SENSITIVE;
    }
  } else if (enif_get_ulong(env, arg, &r)) {
    return r;
  }

  return 0;
}

ERL_NIF_TERM enacl_crypto_pwhash(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]) {
  ErlNifBinary h, p, s;
  size_t o, m;

  // Validate the arguments
  if ((argc != 4) || (!enif_inspect_iolist_as_binary(env, argv[0], &p)) ||
      (!enif_inspect_binary(env, argv[1], &s)) ||
      !(o = enacl_pwhash_opslimit(env, argv[2])) ||
      !(m = enacl_pwhash_memlimit(env, argv[3]))) {
    return enif_make_badarg(env);
  }

  // Check limits
  if ((o < crypto_pwhash_OPSLIMIT_MIN) || (o > crypto_pwhash_OPSLIMIT_MAX) ||
      (m < crypto_pwhash_MEMLIMIT_MIN) || (m > crypto_pwhash_MEMLIMIT_MAX)) {
    return enif_make_badarg(env);
  }

  // Check Salt size
  if (s.size != crypto_pwhash_SALTBYTES) {
    return enacl_error_tuple(env, "invalid_salt_size");
  }

  // Allocate memory for return binary
  if (!enif_alloc_binary(crypto_box_SEEDBYTES, &h)) {
    return enacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_pwhash(h.data, h.size, (char *)p.data, p.size, s.data, o, m,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    enif_release_binary(&h);
    return enacl_error_tuple(env, "out_of_memory");
  }

  ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret = enif_make_binary(env, &h);

  return enif_make_tuple2(env, ok, ret);
}

ERL_NIF_TERM enacl_crypto_pwhash_str(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  ErlNifBinary h, p;
  size_t o, m;

  // Validate the arguments
  if ((argc != 3) || (!enif_inspect_iolist_as_binary(env, argv[0], &p)) ||
      !(o = enacl_pwhash_opslimit(env, argv[1])) ||
      !(m = enacl_pwhash_memlimit(env, argv[2]))) {
    return enif_make_badarg(env);
  }

  // Check limits
  if ((o < crypto_pwhash_OPSLIMIT_MIN) || (o > crypto_pwhash_OPSLIMIT_MAX) ||
      (m < crypto_pwhash_MEMLIMIT_MIN) || (m > crypto_pwhash_MEMLIMIT_MAX)) {
    return enif_make_badarg(env);
  }

  // Allocate memory for return binary
  if (!enif_alloc_binary(crypto_pwhash_STRBYTES, &h)) {
    return enacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_pwhash_str((char *)h.data, (char *)p.data, p.size, o, m) != 0) {
    /* out of memory */
    enif_release_binary(&h);
    return enacl_error_tuple(env, "out_of_memory");
  }

  ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret = enif_make_binary(env, &h);

  return enif_make_tuple2(env, ok, ret);
}

ERL_NIF_TERM enacl_crypto_pwhash_str_verify(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  ErlNifBinary h, p;
  // Validate the arguments
  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &h)) ||
      (!enif_inspect_iolist_as_binary(env, argv[1], &p))) {
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM ret = enif_make_atom(env, ATOM_TRUE);
  if (crypto_pwhash_str_verify((char *)h.data, (char *)p.data, p.size) != 0) {
    /* wrong password */
    ret = enif_make_atom(env, ATOM_FALSE);
  }

  return ret;
}
