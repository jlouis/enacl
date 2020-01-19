#include "erl_nif.h"

#include <sodium.h>
#include <string.h>

#include "aead.h"
#include "enacl.h"
#include "generichash.h"
#include "hash.h"

#define CRYPTO_SIGN_STATE_RESOURCE "crypto_sign_state"

#ifdef ERL_NIF_DIRTY_JOB_CPU_BOUND
#define erl_nif_dirty_job_cpu_bound_macro(a, b, c)                             \
  { a, b, c, ERL_NIF_DIRTY_JOB_CPU_BOUND }
#else
#define erl_nif_dirty_job_cpu_bound_macro(a, b, c)                             \
  { a, b, c }
#endif

//{"crypto_box_keypair", 0, enif_crypto_box_keypair,
// ERL_NIF_DIRTY_JOB_CPU_BOUND}
/* Errors */

/* These are global variables for resource types */
static ErlNifResourceType *sign_state_type = NULL;

/* Initialization */
static int enif_crypto_load(ErlNifEnv *env, void **priv_data,
                            ERL_NIF_TERM load_info) {
  // Create a new resource type for crypto_generichash_state
  if (!enacl_init_generic_hash_ctx(env)) {
    return -1;
  }
  // Create a new resource type for crypto_sign_state
  if (!(sign_state_type =
            enif_open_resource_type(env, NULL, CRYPTO_SIGN_STATE_RESOURCE, NULL,
                                    ERL_NIF_RT_CREATE, NULL))) {
    return -1;
  }

  return sodium_init();
}

static ERL_NIF_TERM enif_crypto_verify_16(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  ErlNifBinary x, y;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &x)) ||
      (!enif_inspect_binary(env, argv[1], &y))) {
    return enif_make_badarg(env);
  }

  if (x.size != 16 || y.size != 16) {
    return enif_make_badarg(env);
  }

  if (0 == crypto_verify_16(x.data, y.data)) {
    return enif_make_atom(env, "true");
  } else {
    return enif_make_atom(env, "false");
  }
}

static ERL_NIF_TERM enif_crypto_verify_32(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  ErlNifBinary x, y;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &x)) ||
      (!enif_inspect_binary(env, argv[1], &y))) {
    return enif_make_badarg(env);
  }

  if (x.size != 32 || y.size != 32) {
    return enif_make_badarg(env);
  }

  if (0 == crypto_verify_32(x.data, y.data)) {
    return enif_make_atom(env, "true");
  } else {
    return enif_make_atom(env, "false");
  }
}

/* This is very unsafe. It will not affect things that have been
  binary_copy()'ed Use this for destroying key material from ram but nothing
  more. Be careful! */
static ERL_NIF_TERM enif_sodium_memzero(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  ErlNifBinary x;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &x))) {
    return enif_make_badarg(env);
  }

  sodium_memzero(x.data, x.size);

  return enif_make_atom(env, "ok");
}

/* Curve 25519 */
static ERL_NIF_TERM
enif_crypto_curve25519_scalarmult(ErlNifEnv *env, int argc,
                                  ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary secret, basepoint, output;
  uint8_t bp[crypto_scalarmult_curve25519_BYTES];

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &secret)) ||
      (!enif_inspect_binary(env, argv[1], &basepoint)) ||
      (secret.size != crypto_scalarmult_curve25519_BYTES) ||
      (basepoint.size != crypto_scalarmult_curve25519_BYTES)) {
    return enif_make_badarg(env);
  }

  memcpy(bp, basepoint.data, crypto_scalarmult_curve25519_BYTES);

  /* Clear the high-bit. Better safe than sorry. */
  bp[crypto_scalarmult_curve25519_BYTES - 1] &= 0x7f;

  do {
    if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &output)) {
      result = nacl_error_tuple(env, "alloc_failed");
      continue;
    }

    if (crypto_scalarmult_curve25519(output.data, secret.data, bp) < 0) {
      result = nacl_error_tuple(env, "scalarmult_curve25519_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  sodium_memzero(bp, crypto_scalarmult_curve25519_BYTES);

  return result;
}

static ERL_NIF_TERM
enif_crypto_curve25519_scalarmult_base(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary secret, output;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &secret)) ||
      (secret.size != crypto_scalarmult_curve25519_BYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &output)) {
      result = nacl_error_tuple(env, "alloc_failed");
      continue;
    }

    if (crypto_scalarmult_curve25519_base(output.data, secret.data) < 0) {
      result = nacl_error_tuple(env, "scalarmult_curve25519_base_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

/* Ed 25519 */
static ERL_NIF_TERM
enif_crypto_sign_ed25519_keypair(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_ed25519_PUBLICKEYBYTES, &pk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_sign_ed25519_SECRETKEYBYTES, &sk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_sign_ed25519_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

static ERL_NIF_TERM
enif_crypto_sign_ed25519_sk_to_pk(ErlNifEnv *env, int argc,
                                  ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &sk)) ||
      (sk.size != crypto_sign_ed25519_SECRETKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_ed25519_PUBLICKEYBYTES, &pk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_sign_ed25519_sk_to_pk(pk.data, sk.data) != 0) {
    return nacl_error_tuple(env, "crypto_sign_ed25519_sk_to_pk_failed");
  }

  return enif_make_binary(env, &pk);
}

static ERL_NIF_TERM
enif_crypto_sign_ed25519_public_to_curve25519(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  ErlNifBinary curve25519_pk, ed25519_pk;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &ed25519_pk)) ||
      (ed25519_pk.size != crypto_sign_ed25519_PUBLICKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &curve25519_pk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_sign_ed25519_pk_to_curve25519(curve25519_pk.data,
                                           ed25519_pk.data) != 0) {
    return nacl_error_tuple(env, "ed25519_public_to_curve25519_failed");
  }

  return enif_make_binary(env, &curve25519_pk);
}

static ERL_NIF_TERM
enif_crypto_sign_ed25519_secret_to_curve25519(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  ErlNifBinary curve25519_sk, ed25519_sk;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &ed25519_sk)) ||
      (ed25519_sk.size != crypto_sign_ed25519_SECRETKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &curve25519_sk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_sign_ed25519_sk_to_curve25519(curve25519_sk.data,
                                           ed25519_sk.data) != 0) {
    return nacl_error_tuple(env, "ed25519_secret_to_curve25519_failed");
  }

  return enif_make_binary(env, &curve25519_sk);
}

static ERL_NIF_TERM
enif_crypto_sign_ed25519_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_ed25519_PUBLICKEYBYTES);
}

static ERL_NIF_TERM
enif_crypto_sign_ed25519_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_ed25519_SECRETKEYBYTES);
}

/* Public-key cryptography */
static ERL_NIF_TERM enif_crypto_box_NONCEBYTES(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_NONCEBYTES);
}

static ERL_NIF_TERM enif_crypto_box_ZEROBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_ZEROBYTES);
}

static ERL_NIF_TERM enif_crypto_box_BOXZEROBYTES(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_BOXZEROBYTES);
}

static ERL_NIF_TERM enif_crypto_box_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_PUBLICKEYBYTES);
}

static ERL_NIF_TERM enif_crypto_box_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_SECRETKEYBYTES);
}

static ERL_NIF_TERM enif_crypto_box_BEFORENMBYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_BEFORENMBYTES);
}

static ERL_NIF_TERM enif_crypto_box_keypair(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_box_PUBLICKEYBYTES, &pk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_box_SECRETKEYBYTES, &sk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_box_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

static ERL_NIF_TERM enif_crypto_box(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  ErlNifBinary padded_msg, nonce, pk, sk, result;

  if ((argc != 4) ||
      (!enif_inspect_iolist_as_binary(env, argv[0], &padded_msg)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &pk)) ||
      (!enif_inspect_binary(env, argv[3], &sk))) {
    return enif_make_badarg(env);
  }

  if ((nonce.size != crypto_box_NONCEBYTES) ||
      (pk.size != crypto_box_PUBLICKEYBYTES) ||
      (sk.size != crypto_box_SECRETKEYBYTES) ||
      (padded_msg.size < crypto_box_ZEROBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(padded_msg.size, &result)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_box(result.data, padded_msg.data, padded_msg.size, nonce.data,
                      pk.data, sk.data)) {
    return nacl_error_tuple(env, "box_error");
  }

  return enif_make_sub_binary(env, enif_make_binary(env, &result),
                              crypto_box_BOXZEROBYTES,
                              padded_msg.size - crypto_box_BOXZEROBYTES);
}

static ERL_NIF_TERM enif_crypto_box_open(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_box_open(result.data, padded_ciphertext.data,
                           padded_ciphertext.size, nonce.data, pk.data,
                           sk.data)) {
    enif_release_binary(&result);
    return nacl_error_tuple(env, "failed_verification");
  }

  return enif_make_sub_binary(env, enif_make_binary(env, &result),
                              crypto_box_ZEROBYTES,
                              padded_ciphertext.size - crypto_box_ZEROBYTES);
}

/* Precomputed crypto boxes */

static ERL_NIF_TERM enif_crypto_box_beforenm(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  ErlNifBinary k, pk, sk;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &pk)) ||
      (!enif_inspect_binary(env, argv[1], &sk)) ||
      (pk.size != crypto_box_PUBLICKEYBYTES) ||
      (sk.size != crypto_box_SECRETKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_box_BEFORENMBYTES, &k)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_box_beforenm(k.data, pk.data, sk.data)) {
    // error
    return nacl_error_tuple(env, "error_gen_shared_secret");
  }

  return enif_make_binary(env, &k);
}

static ERL_NIF_TERM enif_crypto_box_afternm(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_box_afternm(result.data, m.data, m.size, nonce.data, k.data);

  return enif_make_sub_binary(env, enif_make_binary(env, &result),
                              crypto_box_BOXZEROBYTES,
                              m.size - crypto_box_BOXZEROBYTES);
}

static ERL_NIF_TERM enif_crypto_box_open_afternm(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_box_open_afternm(result.data, m.data, m.size, nonce.data,
                                   k.data)) {
    enif_release_binary(&result);
    return nacl_error_tuple(env, "failed_verification");
  }

  return enif_make_sub_binary(env, enif_make_binary(env, &result),
                              crypto_box_ZEROBYTES,
                              m.size - crypto_box_ZEROBYTES);
}

/* Signing */
static ERL_NIF_TERM enif_crypto_sign_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                                    ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_PUBLICKEYBYTES);
}

static ERL_NIF_TERM enif_crypto_sign_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                                    ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_SECRETKEYBYTES);
}

static ERL_NIF_TERM enif_crypto_sign_SEEDBYTES(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_SEEDBYTES);
}

static ERL_NIF_TERM enif_crypto_sign_keypair(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_PUBLICKEYBYTES, &pk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_sign_SECRETKEYBYTES, &sk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_sign_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

static ERL_NIF_TERM enif_crypto_sign_seed_keypair(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk, seed;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &seed))) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_PUBLICKEYBYTES, &pk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_sign_SECRETKEYBYTES, &sk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_sign_seed_keypair(pk.data, sk.data, seed.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

/*
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);
 */
static ERL_NIF_TERM enif_crypto_sign(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  ErlNifBinary m, sk, sm;
  unsigned long long smlen;

  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &sk))) {
    return enif_make_badarg(env);
  }

  if (sk.size != crypto_sign_SECRETKEYBYTES) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(m.size + crypto_sign_BYTES, &sm)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_sign(sm.data, &smlen, m.data, m.size, sk.data);

  return enif_make_sub_binary(env, enif_make_binary(env, &sm), 0, smlen);
}

/*
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);
 */
static ERL_NIF_TERM enif_crypto_sign_open(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  ErlNifBinary m, sm, pk;
  unsigned long long mlen;

  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &sm)) ||
      (!enif_inspect_binary(env, argv[1], &pk))) {
    return enif_make_badarg(env);
  }

  if (pk.size != crypto_sign_PUBLICKEYBYTES) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(sm.size, &m)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 == crypto_sign_open(m.data, &mlen, sm.data, sm.size, pk.data)) {
    return enif_make_sub_binary(env, enif_make_binary(env, &m), 0, mlen);
  } else {
    enif_release_binary(&m);
    return nacl_error_tuple(env, "failed_verification");
  }
}

/*
int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen,
                         const unsigned char *m, unsigned long long mlen,
                         const unsigned char *sk);
 */
static ERL_NIF_TERM enif_crypto_sign_detached(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  ErlNifBinary m, sk, sig;
  unsigned long long siglen;

  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
      (!enif_inspect_binary(env, argv[1], &sk))) {
    return enif_make_badarg(env);
  }

  if (sk.size != crypto_sign_SECRETKEYBYTES) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_BYTES, &sig)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_sign_detached(sig.data, &siglen, m.data, m.size, sk.data);

  return enif_make_binary(env, &sig);
}

/*
int crypto_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk);
 */
static ERL_NIF_TERM
enif_crypto_sign_verify_detached(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]) {
  ErlNifBinary m, sig, pk;

  if ((argc != 3) || (!enif_inspect_binary(env, argv[0], &sig)) ||
      (!enif_inspect_iolist_as_binary(env, argv[1], &m)) ||
      (!enif_inspect_binary(env, argv[2], &pk))) {
    return enif_make_badarg(env);
  }

  if (pk.size != crypto_sign_PUBLICKEYBYTES) {
    return enif_make_badarg(env);
  }

  if (0 == crypto_sign_verify_detached(sig.data, m.data, m.size, pk.data)) {
    return enif_make_atom(env, "true");
  } else {
    return enif_make_atom(env, "false");
  }
}

/*
  int crypto_sign_init(crypto_sign_state *state)
 */

static ERL_NIF_TERM enif_crypto_sign_init(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  if ((argc != 0)) {
    return enif_make_badarg(env);
  }

  void *state = enif_alloc_resource(sign_state_type, crypto_sign_statebytes());

  if (!state) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_sign_init(state)) {
    enif_release_resource(state);
    return nacl_error_tuple(env, "sign_init_error");
  }

  // Create return values
  ERL_NIF_TERM e1 = enif_make_atom(env, "signstate");
  ERL_NIF_TERM e2 = enif_make_resource(env, state);

  // release dynamically allocated memory to erlang to mange
  enif_release_resource(state);

  // return a tuple
  return enif_make_tuple2(env, e1, e2);
}

/*
  int crypto_sign_update(crypto_sign_state *state,
                        const unsigned char *m,
                        unsigned long long mlen);
 */

static ERL_NIF_TERM enif_crypto_sign_update(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  ErlNifBinary data;

  void *state;

  // Validate the arguments
  if ((argc != 2) ||
      (!enif_get_resource(env, argv[0], sign_state_type, (void **)&state)) ||
      (!enif_inspect_binary(env, argv[1], &data))) {
    return enif_make_badarg(env);
  }

  if (0 != crypto_sign_update(state, data.data, data.size)) {
    return nacl_error_tuple(env, "sign_update_error");
  }

  // Generate return value
  ERL_NIF_TERM e1 = enif_make_atom(env, "signstate");
  ERL_NIF_TERM e2 = enif_make_resource(env, state);

  // return a tuple
  return enif_make_tuple2(env, e1, e2);
}

/*
  int crypto_sign_final_create(crypto_sign_state *state,
                               unsigned char *sig,
                               unsigned long long *siglen_p,
                               const unsigned char *sk);
 */

static ERL_NIF_TERM enif_crypto_sign_final_create(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  ErlNifBinary sk, sig;

  void *state;

  unsigned long long siglen;

  if ((argc != 2) ||
      (!enif_get_resource(env, argv[0], sign_state_type, (void **)&state)) ||
      (!enif_inspect_binary(env, argv[1], &sk))) {
    return enif_make_badarg(env);
  }

  if (sk.size != crypto_sign_SECRETKEYBYTES) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_BYTES, &sig)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_sign_final_create(state, sig.data, &siglen, sk.data)) {
    enif_release_binary(&sig);
    return nacl_error_tuple(env, "sign_error");
  }

  ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret = enif_make_binary(env, &sig);

  return enif_make_tuple2(env, ok, ret);
}

/*
  int crypto_sign_final_verify(crypto_sign_state *state,
                               unsigned char *sig,
                               const unsigned char *pk);
 */

static ERL_NIF_TERM enif_crypto_sign_final_verify(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sig;

  void *state;

  if ((argc != 3) ||
      (!enif_get_resource(env, argv[0], sign_state_type, (void **)&state)) ||
      (!enif_inspect_binary(env, argv[1], &sig)) ||
      (!enif_inspect_binary(env, argv[2], &pk))) {
    return enif_make_badarg(env);
  }

  if (pk.size != crypto_sign_PUBLICKEYBYTES) {
    return enif_make_badarg(env);
  }

  if (0 == crypto_sign_final_verify(state, sig.data, pk.data)) {
    return enif_make_atom(env, ATOM_OK);
  }

  return nacl_error_tuple(env, "failed_verification");
}

/* Sealed box functions */

static ERL_NIF_TERM enif_crypto_box_SEALBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_box_SEALBYTES);
}

static ERL_NIF_TERM enif_crypto_box_seal(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, msg, ciphertext;

  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &msg)) ||
      (!enif_inspect_binary(env, argv[1], &key))) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(msg.size + crypto_box_SEALBYTES, &ciphertext)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_box_seal(ciphertext.data, msg.data, msg.size, key.data);

  return enif_make_binary(env, &ciphertext);
}

static ERL_NIF_TERM enif_crypto_box_seal_open(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_box_seal_open(msg.data, ciphertext.data, ciphertext.size, pk.data,
                           sk.data) != 0) {
    enif_release_binary(&msg);
    return nacl_error_tuple(env, "failed_verification");
  }

  return enif_make_binary(env, &msg);
}

/* Secret key cryptography */

static ERL_NIF_TERM
enif_crypto_secretbox_NONCEBYTES(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_secretbox_NONCEBYTES);
}

static ERL_NIF_TERM enif_crypto_secretbox_KEYBYTES(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_secretbox_KEYBYTES);
}

static ERL_NIF_TERM enif_crypto_secretbox_ZEROBYTES(ErlNifEnv *env, int argc,
                                                    ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_secretbox_ZEROBYTES);
}

static ERL_NIF_TERM
enif_crypto_secretbox_BOXZEROBYTES(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_secretbox_BOXZEROBYTES);
}

static ERL_NIF_TERM
enif_crypto_stream_chacha20_KEYBYTES(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_stream_chacha20_KEYBYTES);
}

static ERL_NIF_TERM
enif_crypto_stream_chacha20_NONCEBYTES(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_stream_chacha20_NONCEBYTES);
}

static ERL_NIF_TERM enif_crypto_stream_KEYBYTES(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_stream_KEYBYTES);
}

static ERL_NIF_TERM enif_crypto_stream_NONCEBYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_stream_NONCEBYTES);
}

static ERL_NIF_TERM enif_crypto_auth_BYTES(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_auth_BYTES);
}

static ERL_NIF_TERM enif_crypto_auth_KEYBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_auth_KEYBYTES);
}

static ERL_NIF_TERM enif_crypto_shorthash_BYTES(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_shorthash_BYTES);
}

static ERL_NIF_TERM enif_crypto_shorthash_KEYBYTES(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_shorthash_KEYBYTES);
}

static ERL_NIF_TERM enif_crypto_onetimeauth_BYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_onetimeauth_BYTES);
}

static ERL_NIF_TERM
enif_crypto_onetimeauth_KEYBYTES(ErlNifEnv *env, int argc,
                                 ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_onetimeauth_KEYBYTES);
}

static ERL_NIF_TERM enif_crypto_secretbox(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_secretbox(padded_ciphertext.data, padded_msg.data, padded_msg.size,
                   nonce.data, key.data);

  return enif_make_sub_binary(env, enif_make_binary(env, &padded_ciphertext),
                              crypto_secretbox_BOXZEROBYTES,
                              padded_msg.size - crypto_secretbox_BOXZEROBYTES);
}

static ERL_NIF_TERM enif_crypto_secretbox_open(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_secretbox_open(padded_msg.data, padded_ciphertext.data,
                            padded_ciphertext.size, nonce.data,
                            key.data) != 0) {
    enif_release_binary(&padded_msg);
    return nacl_error_tuple(env, "failed_verification");
  }

  return enif_make_sub_binary(
      env, enif_make_binary(env, &padded_msg), crypto_secretbox_ZEROBYTES,
      padded_ciphertext.size - crypto_secretbox_ZEROBYTES);
}

static ERL_NIF_TERM enif_crypto_stream_chacha20(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_stream_chacha20(c.data, c.size, n.data, k.data);

  return enif_make_binary(env, &c);
}

static ERL_NIF_TERM enif_crypto_stream_chacha20_xor(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_stream_chacha20_xor(c.data, m.data, m.size, n.data, k.data);

  return enif_make_binary(env, &c);
}

static ERL_NIF_TERM enif_crypto_stream(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_stream(c.data, c.size, n.data, k.data);

  return enif_make_binary(env, &c);
}

static ERL_NIF_TERM enif_crypto_stream_xor(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_stream_xor(c.data, m.data, m.size, n.data, k.data);

  return enif_make_binary(env, &c);
}

static ERL_NIF_TERM enif_crypto_auth(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_auth(a.data, m.data, m.size, k.data);

  return enif_make_binary(env, &a);
}

static ERL_NIF_TERM enif_crypto_auth_verify(ErlNifEnv *env, int argc,
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

static ERL_NIF_TERM enif_crypto_shorthash(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_shorthash(a.data, m.data, m.size, k.data);

  return enif_make_binary(env, &a);
}

static ERL_NIF_TERM enif_crypto_onetimeauth(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_onetimeauth(a.data, m.data, m.size, k.data);

  return enif_make_binary(env, &a);
}

static ERL_NIF_TERM enif_crypto_onetimeauth_verify(ErlNifEnv *env, int argc,
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

static ERL_NIF_TERM enif_randombytes(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  unsigned req_size;
  ErlNifBinary result;

  if ((argc != 1) || (!enif_get_uint(env, argv[0], &req_size))) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(req_size, &result)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  randombytes(result.data, result.size);

  return enif_make_binary(env, &result);
}

static ERL_NIF_TERM enif_randombytes_uint32(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  ErlNifUInt64 result;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  result = randombytes_random();
  return enif_make_uint64(env, result);
}

static ERL_NIF_TERM enif_randombytes_uniform(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  unsigned upper_bound;
  ErlNifUInt64 result;

  if ((argc != 1) || (!enif_get_uint(env, argv[0], &upper_bound))) {
    return enif_make_badarg(env);
  }

  result = randombytes_uniform(upper_bound);
  return enif_make_uint64(env, result);
}

/* Key exchange */

static ERL_NIF_TERM enif_crypto_kx_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_kx_SECRETKEYBYTES);
}

static ERL_NIF_TERM enif_crypto_kx_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_kx_PUBLICKEYBYTES);
}

static ERL_NIF_TERM enif_crypto_kx_SESSIONKEYBYTES(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_kx_SESSIONKEYBYTES);
}

static ERL_NIF_TERM enif_crypto_kx_keypair(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_kx_PUBLICKEYBYTES, &pk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_kx_SECRETKEYBYTES, &sk)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_kx_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

static ERL_NIF_TERM
enif_crypto_kx_server_session_keys(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]) {
  ErlNifBinary rx, tx, server_pk, server_sk, client_pk;

  if ((argc != 3) || (!enif_inspect_binary(env, argv[0], &server_pk)) ||
      (!enif_inspect_binary(env, argv[1], &server_sk)) ||
      (!enif_inspect_binary(env, argv[2], &client_pk)) ||
      (server_pk.size != crypto_kx_PUBLICKEYBYTES) ||
      (server_sk.size != crypto_kx_SECRETKEYBYTES) ||
      (client_pk.size != crypto_kx_PUBLICKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_kx_SESSIONKEYBYTES, &rx)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_kx_SESSIONKEYBYTES, &tx)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_kx_server_session_keys(rx.data, tx.data, server_pk.data,
                                         server_sk.data, client_pk.data)) {
    // suspicious client public key
    return nacl_error_tuple(env, "invalid_client_public_key");
  }

  return enif_make_tuple2(env, enif_make_binary(env, &rx),
                          enif_make_binary(env, &tx));
}

static ERL_NIF_TERM
enif_crypto_kx_client_session_keys(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]) {
  ErlNifBinary rx, tx, client_pk, client_sk, server_pk;

  if ((argc != 3) || (!enif_inspect_binary(env, argv[0], &client_pk)) ||
      (!enif_inspect_binary(env, argv[1], &client_sk)) ||
      (!enif_inspect_binary(env, argv[2], &server_pk)) ||
      (client_pk.size != crypto_kx_PUBLICKEYBYTES) ||
      (client_sk.size != crypto_kx_SECRETKEYBYTES) ||
      (server_pk.size != crypto_kx_PUBLICKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_kx_SESSIONKEYBYTES, &rx)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (!enif_alloc_binary(crypto_kx_SESSIONKEYBYTES, &tx)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (0 != crypto_kx_client_session_keys(rx.data, tx.data, client_pk.data,
                                         client_sk.data, server_pk.data)) {
    // suspicious server public key
    return nacl_error_tuple(env, "invalid_server_public_key");
  }

  return enif_make_tuple2(env, enif_make_binary(env, &rx),
                          enif_make_binary(env, &tx));
}

/* Various other helper functions */
static void uint64_pack(unsigned char *y, ErlNifUInt64 x) {
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
}

static ErlNifUInt64 uint64_unpack(const unsigned char *x) {
  ErlNifUInt64 result;

  result = x[7];
  result <<= 8;
  result |= x[6];
  result <<= 8;
  result |= x[5];
  result <<= 8;
  result |= x[4];
  result <<= 8;
  result |= x[3];
  result <<= 8;
  result |= x[2];
  result <<= 8;
  result |= x[1];
  result <<= 8;
  result |= x[0];
  return result;
}
static int crypto_block(unsigned char *out, const unsigned char *in,
                        const unsigned char *k) {
  ErlNifUInt64 v0 = uint64_unpack(in + 0);
  ErlNifUInt64 v1 = uint64_unpack(in + 8);
  ErlNifUInt64 k0 = uint64_unpack(k + 0);
  ErlNifUInt64 k1 = uint64_unpack(k + 8);
  ErlNifUInt64 k2 = uint64_unpack(k + 16);
  ErlNifUInt64 k3 = uint64_unpack(k + 24);
  ErlNifUInt64 sum = 0;
  ErlNifUInt64 delta = 0x9e3779b97f4a7c15;
  int i;
  for (i = 0; i < 32; ++i) {
    sum += delta;
    v0 += ((v1 << 7) + k0) ^ (v1 + sum) ^ ((v1 >> 12) + k1);
    v1 += ((v0 << 16) + k2) ^ (v0 + sum) ^ ((v0 >> 8) + k3);
  }
  uint64_pack(out + 0, v0);
  uint64_pack(out + 8, v1);

  return 0;
}

static ERL_NIF_TERM enif_scramble_block_16(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  ErlNifBinary in, out, key;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &in)) ||
      (!enif_inspect_binary(env, argv[1], &key)) || (in.size != 16) ||
      (key.size != 32)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(in.size, &out)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  crypto_block(out.data, in.data, key.data);

  return enif_make_binary(env, &out);
}

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

static ERL_NIF_TERM enif_crypto_pwhash(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "invalid_salt_size");
  }

  // Allocate memory for return binary
  if (!enif_alloc_binary(crypto_box_SEEDBYTES, &h)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_pwhash(h.data, h.size, (char *)p.data, p.size, s.data, o, m,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    enif_release_binary(&h);
    return nacl_error_tuple(env, "out_of_memory");
  }

  ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret = enif_make_binary(env, &h);

  return enif_make_tuple2(env, ok, ret);
}

static ERL_NIF_TERM enif_crypto_pwhash_str(ErlNifEnv *env, int argc,
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
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_pwhash_str((char *)h.data, (char *)p.data, p.size, o, m) != 0) {
    /* out of memory */
    enif_release_binary(&h);
    return nacl_error_tuple(env, "out_of_memory");
  }

  ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM ret = enif_make_binary(env, &h);

  return enif_make_tuple2(env, ok, ret);
}

static ERL_NIF_TERM enif_crypto_pwhash_str_verify(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  ErlNifBinary h, p;

  // Validate the arguments
  if ((argc != 2) || (!enif_inspect_iolist_as_binary(env, argv[0], &h)) ||
      (!enif_inspect_iolist_as_binary(env, argv[1], &p))) {
    return enif_make_badarg(env);
  }

  ERL_NIF_TERM retVal = enif_make_atom(env, ATOM_TRUE);
  if (crypto_pwhash_str_verify((char *)h.data, (char *)p.data, p.size) != 0) {
    /* wrong password */
    retVal = enif_make_atom(env, ATOM_FALSE);
  }

  return retVal;
}

/* Tie the knot to the Erlang world */
static ErlNifFunc nif_funcs[] = {
    {"crypto_box_NONCEBYTES", 0, enif_crypto_box_NONCEBYTES},
    {"crypto_box_ZEROBYTES", 0, enif_crypto_box_ZEROBYTES},
    {"crypto_box_BOXZEROBYTES", 0, enif_crypto_box_BOXZEROBYTES},
    {"crypto_box_PUBLICKEYBYTES", 0, enif_crypto_box_PUBLICKEYBYTES},
    {"crypto_box_SECRETKEYBYTES", 0, enif_crypto_box_SECRETKEYBYTES},
    {"crypto_box_BEFORENMBYTES", 0, enif_crypto_box_BEFORENMBYTES},

    erl_nif_dirty_job_cpu_bound_macro("crypto_box_keypair", 0,
                                      enif_crypto_box_keypair),

    erl_nif_dirty_job_cpu_bound_macro("crypto_box", 4, enif_crypto_box),
    erl_nif_dirty_job_cpu_bound_macro("crypto_box_open", 4,
                                      enif_crypto_box_open),

    {"crypto_box_beforenm", 2, enif_crypto_box_beforenm},
    {"crypto_box_afternm_b", 3, enif_crypto_box_afternm},
    erl_nif_dirty_job_cpu_bound_macro("crypto_box_afternm", 3,
                                      enif_crypto_box_afternm),
    {"crypto_box_open_afternm_b", 3, enif_crypto_box_open_afternm},
    erl_nif_dirty_job_cpu_bound_macro("crypto_box_open_afternm", 3,
                                      enif_crypto_box_open_afternm),

    {"crypto_sign_PUBLICKEYBYTES", 0, enif_crypto_sign_PUBLICKEYBYTES},
    {"crypto_sign_SECRETKEYBYTES", 0, enif_crypto_sign_SECRETKEYBYTES},
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_keypair", 0,
                                      enif_crypto_sign_keypair),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_seed_keypair", 1,
                                      enif_crypto_sign_seed_keypair),

    erl_nif_dirty_job_cpu_bound_macro("crypto_sign", 2, enif_crypto_sign),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_open", 2,
                                      enif_crypto_sign_open),

    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_detached", 2,
                                      enif_crypto_sign_detached),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_verify_detached", 3,
                                      enif_crypto_sign_verify_detached),
    {"crypto_sign_init", 0, enif_crypto_sign_init},
    {"crypto_sign_update", 2, enif_crypto_sign_update},
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_final_create", 2,
                                      enif_crypto_sign_final_create),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_final_verify", 3,
                                      enif_crypto_sign_final_verify),

    {"crypto_sign_ed25519_sk_to_pk", 1, enif_crypto_sign_ed25519_sk_to_pk},

    {"crypto_box_SEALBYTES", 0, enif_crypto_box_SEALBYTES},

    erl_nif_dirty_job_cpu_bound_macro("crypto_box_seal", 2,
                                      enif_crypto_box_seal),
    erl_nif_dirty_job_cpu_bound_macro("crypto_box_seal_open", 3,
                                      enif_crypto_box_seal_open),

    {"crypto_secretbox_NONCEBYTES", 0, enif_crypto_secretbox_NONCEBYTES},
    {"crypto_secretbox_ZEROBYTES", 0, enif_crypto_secretbox_ZEROBYTES},
    {"crypto_secretbox_BOXZEROBYTES", 0, enif_crypto_secretbox_BOXZEROBYTES},
    {"crypto_secretbox_KEYBYTES", 0, enif_crypto_secretbox_KEYBYTES},
    {"crypto_secretbox_b", 3, enif_crypto_secretbox},
    erl_nif_dirty_job_cpu_bound_macro("crypto_secretbox", 3,
                                      enif_crypto_secretbox),
    {"crypto_secretbox_open_b", 3, enif_crypto_secretbox_open},
    erl_nif_dirty_job_cpu_bound_macro("crypto_secretbox_open", 3,
                                      enif_crypto_secretbox_open),

    {"crypto_stream_chacha20_KEYBYTES", 0,
     enif_crypto_stream_chacha20_KEYBYTES},
    {"crypto_stream_chacha20_NONCEBYTES", 0,
     enif_crypto_stream_chacha20_NONCEBYTES},
    {"crypto_stream_chacha20_b", 3, enif_crypto_stream_chacha20},
    erl_nif_dirty_job_cpu_bound_macro("crypto_stream_chacha20", 3,
                                      enif_crypto_stream_chacha20),
    {"crypto_stream_chacha20_xor_b", 3, enif_crypto_stream_chacha20_xor},
    erl_nif_dirty_job_cpu_bound_macro("crypto_stream_chacha20_xor", 3,
                                      enif_crypto_stream_chacha20_xor),

    {"crypto_stream_KEYBYTES", 0, enif_crypto_stream_KEYBYTES},
    {"crypto_stream_NONCEBYTES", 0, enif_crypto_stream_NONCEBYTES},
    {"crypto_stream_b", 3, enif_crypto_stream},
    erl_nif_dirty_job_cpu_bound_macro("crypto_stream", 3, enif_crypto_stream),
    {"crypto_stream_xor_b", 3, enif_crypto_stream_xor},
    erl_nif_dirty_job_cpu_bound_macro("crypto_stream_xor", 3,
                                      enif_crypto_stream_xor),

    {"crypto_auth_BYTES", 0, enif_crypto_auth_BYTES},
    {"crypto_auth_KEYBYTES", 0, enif_crypto_auth_KEYBYTES},
    {"crypto_auth_b", 2, enif_crypto_auth},
    erl_nif_dirty_job_cpu_bound_macro("crypto_auth", 2, enif_crypto_auth),
    {"crypto_auth_verify_b", 3, enif_crypto_auth_verify},
    erl_nif_dirty_job_cpu_bound_macro("crypto_auth_verify", 3,
                                      enif_crypto_auth_verify),

    {"crypto_shorthash_BYTES", 0, enif_crypto_shorthash_BYTES},
    {"crypto_shorthash_KEYBYTES", 0, enif_crypto_shorthash_KEYBYTES},
    {"crypto_shorthash", 2, enif_crypto_shorthash},

    {"crypto_onetimeauth_BYTES", 0, enif_crypto_onetimeauth_BYTES},
    {"crypto_onetimeauth_KEYBYTES", 0, enif_crypto_onetimeauth_KEYBYTES},
    {"crypto_onetimeauth_b", 2, enif_crypto_onetimeauth},
    erl_nif_dirty_job_cpu_bound_macro("crypto_onetimeauth", 2,
                                      enif_crypto_onetimeauth),
    {"crypto_onetimeauth_verify_b", 3, enif_crypto_onetimeauth_verify},
    erl_nif_dirty_job_cpu_bound_macro("crypto_onetimeauth_verify", 3,
                                      enif_crypto_onetimeauth_verify),

    {"crypto_hash_b", 1, enacl_crypto_hash},
    erl_nif_dirty_job_cpu_bound_macro("crypto_hash", 1, enacl_crypto_hash),
    {"crypto_verify_16", 2, enif_crypto_verify_16},
    {"crypto_verify_32", 2, enif_crypto_verify_32},
    {"sodium_memzero", 1, enif_sodium_memzero},

    erl_nif_dirty_job_cpu_bound_macro("crypto_pwhash", 4, enif_crypto_pwhash),
    erl_nif_dirty_job_cpu_bound_macro("crypto_pwhash_str", 3,
                                      enif_crypto_pwhash_str),
    erl_nif_dirty_job_cpu_bound_macro("crypto_pwhash_str_verify", 2,
                                      enif_crypto_pwhash_str_verify),

    erl_nif_dirty_job_cpu_bound_macro("crypto_curve25519_scalarmult", 2,
                                      enif_crypto_curve25519_scalarmult),
    erl_nif_dirty_job_cpu_bound_macro("crypto_curve25519_scalarmult_base", 1,
                                      enif_crypto_curve25519_scalarmult_base),

    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_ed25519_keypair", 0,
                                      enif_crypto_sign_ed25519_keypair),
    {"crypto_sign_ed25519_public_to_curve25519", 1,
     enif_crypto_sign_ed25519_public_to_curve25519},
    {"crypto_sign_ed25519_secret_to_curve25519", 1,
     enif_crypto_sign_ed25519_secret_to_curve25519},
    {"crypto_sign_ed25519_PUBLICKEYBYTES", 0,
     enif_crypto_sign_ed25519_PUBLICKEYBYTES},
    {"crypto_sign_ed25519_SECRETKEYBYTES", 0,
     enif_crypto_sign_ed25519_SECRETKEYBYTES},

    // Linux might block here if early in the boot sequence, so get it off the
    // main scheduler. Otherwise, it it would probably be fine to run on the
    // main scheduler. This plays it safe, albeit with a performance hit.
    erl_nif_dirty_job_cpu_bound_macro("randombytes", 1, enif_randombytes),
    erl_nif_dirty_job_cpu_bound_macro("randombytes_uint32", 0,
                                      enif_randombytes_uint32),
    erl_nif_dirty_job_cpu_bound_macro("randombytes_uniform", 1,
                                      enif_randombytes_uniform),

    erl_nif_dirty_job_cpu_bound_macro("crypto_kx_keypair", 0,
                                      enif_crypto_kx_keypair),
    erl_nif_dirty_job_cpu_bound_macro("crypto_kx_client_session_keys", 3,
                                      enif_crypto_kx_client_session_keys),
    erl_nif_dirty_job_cpu_bound_macro("crypto_kx_server_session_keys", 3,
                                      enif_crypto_kx_server_session_keys),
    {"crypto_kx_PUBLICKEYBYTES", 0, enif_crypto_kx_PUBLICKEYBYTES},
    {"crypto_kx_SECRETKEYBYTES", 0, enif_crypto_kx_SECRETKEYBYTES},
    {"crypto_kx_SESSIONKEYBYTES", 0, enif_crypto_kx_SESSIONKEYBYTES},

    {"scramble_block_16", 2, enif_scramble_block_16},

    {"crypto_aead_chacha20poly1305_KEYBYTES", 0,
     enacl_crypto_aead_chacha20poly1305_KEYBYTES},
    {"crypto_aead_chacha20poly1305_NPUBBYTES", 0,
     enacl_crypto_aead_chacha20poly1305_NPUBBYTES},
    {"crypto_aead_chacha20poly1305_ABYTES", 0,
     enacl_crypto_aead_chacha20poly1305_ABYTES},
    {"crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX", 0,
     enacl_crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX},
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_aead_chacha20poly1305_encrypt", 4,
        enacl_crypto_aead_chacha20poly1305_encrypt),
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_aead_chacha20poly1305_decrypt", 4,
        enacl_crypto_aead_chacha20poly1305_decrypt),

    {"crypto_aead_xchacha20poly1305_KEYBYTES", 0,
     enacl_crypto_aead_xchacha20poly1305_KEYBYTES},
    {"crypto_aead_xchacha20poly1305_NPUBBYTES", 0,
     enacl_crypto_aead_xchacha20poly1305_NPUBBYTES},
    {"crypto_aead_xchacha20poly1305_ABYTES", 0,
     enacl_crypto_aead_xchacha20poly1305_ABYTES},
    {"crypto_aead_xchacha20poly1305_MESSAGEBYTES_MAX", 0,
     enacl_crypto_aead_xchacha20poly1305_MESSAGEBYTES_MAX},
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_aead_xchacha20poly1305_encrypt", 4,
        enacl_crypto_aead_xchacha20poly1305_encrypt),
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_aead_xchacha20poly1305_decrypt", 4,
        enacl_crypto_aead_xchacha20poly1305_decrypt),

    {"crypto_generichash_BYTES", 0, enif_crypto_generichash_BYTES},
    {"crypto_generichash_BYTES_MIN", 0, enif_crypto_generichash_BYTES_MIN},
    {"crypto_generichash_BYTES_MAX", 0, enif_crypto_generichash_BYTES_MAX},
    {"crypto_generichash_KEYBYTES", 0, enif_crypto_generichash_KEYBYTES},
    {"crypto_generichash_KEYBYTES_MIN", 0,
     enif_crypto_generichash_KEYBYTES_MIN},
    {"crypto_generichash_KEYBYTES_MAX", 0,
     enif_crypto_generichash_KEYBYTES_MAX},
    {"crypto_generichash", 3, enacl_crypto_generichash},
    {"crypto_generichash_init", 2, enacl_crypto_generichash_init},
    {"crypto_generichash_update", 2, enacl_crypto_generichash_update},
    {"crypto_generichash_final", 1, enacl_crypto_generichash_final}

};

ERL_NIF_INIT(enacl_nif, nif_funcs, enif_crypto_load, NULL, NULL, NULL);
