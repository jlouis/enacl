#include <sodium.h>
#include <string.h>

#include <erl_nif.h>

#include "aead.h"
#include "enacl.h"
#include "enacl_ext.h"
#include "generichash.h"
#include "hash.h"
#include "kdf.h"
#include "kx.h"
#include "public.h"
#include "pwhash.h"
#include "randombytes.h"
#include "secret.h"
#include "secretstream.h"
#include "sign.h"

#ifdef ERL_NIF_DIRTY_JOB_CPU_BOUND
#define erl_nif_dirty_job_cpu_bound_macro(a, b, c)                             \
  { a, b, c, ERL_NIF_DIRTY_JOB_CPU_BOUND }
#else
#define erl_nif_dirty_job_cpu_bound_macro(a, b, c)                             \
  { a, b, c }
#endif

/* Initialization */
static int enacl_crypto_load(ErlNifEnv *env, void **priv_data,
                             ERL_NIF_TERM load_info) {
  // Create a new resource type for crypto_generichash_state
  if (!enacl_init_generic_hash_ctx(env)) {
    return -1;
  }

  if (!enacl_init_sign_ctx(env)) {
    return -1;
  }

  if (!enacl_init_secretstream_ctx(env)) {
    return -1;
  }

  if (sodium_init() == -1) {
    return -1;
  }

  return 0;
}

/* GENERAL ROUTINES
 *
 * These don't generally fit somewhere else nicely, so we keep them in the main
 * file
 *
 */
static ERL_NIF_TERM enacl_crypto_verify_16(ErlNifEnv *env, int argc,
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

static ERL_NIF_TERM enacl_crypto_verify_32(ErlNifEnv *env, int argc,
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
enacl_crypto_curve25519_scalarmult(ErlNifEnv *env, int argc,
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
      result = enacl_internal_error(env);
      continue;
    }

    if (crypto_scalarmult_curve25519(output.data, secret.data, bp) != 0) {
      enif_release_binary(&output);
      result = enacl_error_tuple(env, "scalarmult_curve25519_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  sodium_memzero(bp, crypto_scalarmult_curve25519_BYTES);

  return result;
}

static ERL_NIF_TERM
enacl_crypto_curve25519_scalarmult_base(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary secret, output;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &secret)) ||
      (secret.size != crypto_scalarmult_curve25519_BYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    if (crypto_scalarmult_curve25519_base(output.data, secret.data) != 0) {
      enif_release_binary(&output);
      result = enacl_error_tuple(env, "scalarmult_curve25519_base_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

/* Tie the knot to the Erlang world */
static ErlNifFunc nif_funcs[] = {
    {"crypto_box_NONCEBYTES", 0, enacl_crypto_box_NONCEBYTES},
    {"crypto_box_ZEROBYTES", 0, enacl_crypto_box_ZEROBYTES},
    {"crypto_box_BOXZEROBYTES", 0, enacl_crypto_box_BOXZEROBYTES},
    {"crypto_box_PUBLICKEYBYTES", 0, enacl_crypto_box_PUBLICKEYBYTES},
    {"crypto_box_SECRETKEYBYTES", 0, enacl_crypto_box_SECRETKEYBYTES},
    {"crypto_box_BEFORENMBYTES", 0, enacl_crypto_box_BEFORENMBYTES},

    erl_nif_dirty_job_cpu_bound_macro("crypto_box_keypair", 0,
                                      enacl_crypto_box_keypair),

    erl_nif_dirty_job_cpu_bound_macro("crypto_box", 4, enacl_crypto_box),
    erl_nif_dirty_job_cpu_bound_macro("crypto_box_open", 4,
                                      enacl_crypto_box_open),

    {"crypto_box_beforenm", 2, enacl_crypto_box_beforenm},
    {"crypto_box_afternm_b", 3, enacl_crypto_box_afternm},
    erl_nif_dirty_job_cpu_bound_macro("crypto_box_afternm", 3,
                                      enacl_crypto_box_afternm),
    {"crypto_box_open_afternm_b", 3, enacl_crypto_box_open_afternm},
    erl_nif_dirty_job_cpu_bound_macro("crypto_box_open_afternm", 3,
                                      enacl_crypto_box_open_afternm),

    {"crypto_sign_PUBLICKEYBYTES", 0, enacl_crypto_sign_PUBLICKEYBYTES},
    {"crypto_sign_SECRETKEYBYTES", 0, enacl_crypto_sign_SECRETKEYBYTES},
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_keypair", 0,
                                      enacl_crypto_sign_keypair),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_seed_keypair", 1,
                                      enacl_crypto_sign_seed_keypair),

    erl_nif_dirty_job_cpu_bound_macro("crypto_sign", 2, enacl_crypto_sign),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_open", 2,
                                      enacl_crypto_sign_open),

    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_detached", 2,
                                      enacl_crypto_sign_detached),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_verify_detached", 3,
                                      enacl_crypto_sign_verify_detached),
    {"crypto_sign_init", 0, enacl_crypto_sign_init},
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_update", 2,
                                      enacl_crypto_sign_update),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_final_create", 2,
                                      enacl_crypto_sign_final_create),
    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_final_verify", 3,
                                      enacl_crypto_sign_final_verify),

    {"crypto_sign_ed25519_sk_to_pk", 1, enacl_crypto_sign_ed25519_sk_to_pk},

    {"crypto_box_SEALBYTES", 0, enacl_crypto_box_SEALBYTES},

    erl_nif_dirty_job_cpu_bound_macro("crypto_box_seal", 2,
                                      enacl_crypto_box_seal),
    erl_nif_dirty_job_cpu_bound_macro("crypto_box_seal_open", 3,
                                      enacl_crypto_box_seal_open),

    {"crypto_secretbox_NONCEBYTES", 0, enacl_crypto_secretbox_NONCEBYTES},
    {"crypto_secretbox_ZEROBYTES", 0, enacl_crypto_secretbox_ZEROBYTES},
    {"crypto_secretbox_BOXZEROBYTES", 0, enacl_crypto_secretbox_BOXZEROBYTES},
    {"crypto_secretbox_KEYBYTES", 0, enacl_crypto_secretbox_KEYBYTES},
    {"crypto_secretbox_b", 3, enacl_crypto_secretbox},
    erl_nif_dirty_job_cpu_bound_macro("crypto_secretbox", 3,
                                      enacl_crypto_secretbox),
    {"crypto_secretbox_open_b", 3, enacl_crypto_secretbox_open},
    erl_nif_dirty_job_cpu_bound_macro("crypto_secretbox_open", 3,
                                      enacl_crypto_secretbox_open),

    {"crypto_stream_chacha20_KEYBYTES", 0,
     enacl_crypto_stream_chacha20_KEYBYTES},
    {"crypto_stream_chacha20_NONCEBYTES", 0,
     enacl_crypto_stream_chacha20_NONCEBYTES},
    {"crypto_stream_chacha20_b", 3, enacl_crypto_stream_chacha20},
    erl_nif_dirty_job_cpu_bound_macro("crypto_stream_chacha20", 3,
                                      enacl_crypto_stream_chacha20),
    {"crypto_stream_chacha20_xor_b", 3, enacl_crypto_stream_chacha20_xor},
    erl_nif_dirty_job_cpu_bound_macro("crypto_stream_chacha20_xor", 3,
                                      enacl_crypto_stream_chacha20_xor),

    {"crypto_stream_KEYBYTES", 0, enacl_crypto_stream_KEYBYTES},
    {"crypto_stream_NONCEBYTES", 0, enacl_crypto_stream_NONCEBYTES},
    {"crypto_stream_b", 3, enacl_crypto_stream},
    erl_nif_dirty_job_cpu_bound_macro("crypto_stream", 3, enacl_crypto_stream),
    {"crypto_stream_xor_b", 3, enacl_crypto_stream_xor},
    erl_nif_dirty_job_cpu_bound_macro("crypto_stream_xor", 3,
                                      enacl_crypto_stream_xor),

    {"crypto_auth_BYTES", 0, enacl_crypto_auth_BYTES},
    {"crypto_auth_KEYBYTES", 0, enacl_crypto_auth_KEYBYTES},
    {"crypto_auth_b", 2, enacl_crypto_auth},
    erl_nif_dirty_job_cpu_bound_macro("crypto_auth", 2, enacl_crypto_auth),
    {"crypto_auth_verify_b", 3, enacl_crypto_auth_verify},
    erl_nif_dirty_job_cpu_bound_macro("crypto_auth_verify", 3,
                                      enacl_crypto_auth_verify),

    {"crypto_shorthash_BYTES", 0, enacl_crypto_shorthash_BYTES},
    {"crypto_shorthash_KEYBYTES", 0, enacl_crypto_shorthash_KEYBYTES},
    {"crypto_shorthash", 2, enacl_crypto_shorthash},

    {"crypto_onetimeauth_BYTES", 0, enacl_crypto_onetimeauth_BYTES},
    {"crypto_onetimeauth_KEYBYTES", 0, enacl_crypto_onetimeauth_KEYBYTES},
    {"crypto_onetimeauth_b", 2, enacl_crypto_onetimeauth},
    erl_nif_dirty_job_cpu_bound_macro("crypto_onetimeauth", 2,
                                      enacl_crypto_onetimeauth),
    {"crypto_onetimeauth_verify_b", 3, enacl_crypto_onetimeauth_verify},
    erl_nif_dirty_job_cpu_bound_macro("crypto_onetimeauth_verify", 3,
                                      enacl_crypto_onetimeauth_verify),

    {"crypto_hash_b", 1, enacl_crypto_hash},
    erl_nif_dirty_job_cpu_bound_macro("crypto_hash", 1, enacl_crypto_hash),
    {"crypto_verify_16", 2, enacl_crypto_verify_16},
    {"crypto_verify_32", 2, enacl_crypto_verify_32},
    {"sodium_memzero", 1, enif_sodium_memzero},

    {"crypto_pwhash_SALTBYTES", 0, enacl_crypto_pwhash_SALTBYTES},
    erl_nif_dirty_job_cpu_bound_macro("crypto_pwhash", 5, enacl_crypto_pwhash),
    erl_nif_dirty_job_cpu_bound_macro("crypto_pwhash_str", 3,
                                      enacl_crypto_pwhash_str),
    erl_nif_dirty_job_cpu_bound_macro("crypto_pwhash_str_verify", 2,
                                      enacl_crypto_pwhash_str_verify),

    {"crypto_kdf_KEYBYTES", 0, enacl_crypto_kdf_KEYBYTES},
    {"crypto_kdf_CONTEXTBYTES", 0, enacl_crypto_kdf_CONTEXTBYTES},
    erl_nif_dirty_job_cpu_bound_macro("crypto_kdf_derive_from_key", 3,
                                      enacl_crypto_kdf_derive_from_key),

    erl_nif_dirty_job_cpu_bound_macro("crypto_curve25519_scalarmult", 2,
                                      enacl_crypto_curve25519_scalarmult),
    erl_nif_dirty_job_cpu_bound_macro("crypto_curve25519_scalarmult_base", 1,
                                      enacl_crypto_curve25519_scalarmult_base),

    erl_nif_dirty_job_cpu_bound_macro("crypto_sign_ed25519_keypair", 0,
                                      enacl_crypto_sign_ed25519_keypair),
    {"crypto_sign_ed25519_public_to_curve25519", 1,
     enacl_crypto_sign_ed25519_public_to_curve25519},
    {"crypto_sign_ed25519_secret_to_curve25519", 1,
     enacl_crypto_sign_ed25519_secret_to_curve25519},
    {"crypto_sign_ed25519_PUBLICKEYBYTES", 0,
     enacl_crypto_sign_ed25519_PUBLICKEYBYTES},
    {"crypto_sign_ed25519_SECRETKEYBYTES", 0,
     enacl_crypto_sign_ed25519_SECRETKEYBYTES},

    // Linux might block here if early in the boot sequence, so get it off the
    // main scheduler. Otherwise, it it would probably be fine to run on the
    // main scheduler. This plays it safe, albeit with a performance hit.
    //
    // However: you shouldn't use a CSPRNG unless you need one. So it is
    // probably fine to do the dirty-scheduler dance. Using the random
    // material should dwarf the extraction of random material.
    erl_nif_dirty_job_cpu_bound_macro("randombytes", 1, enif_randombytes),
    erl_nif_dirty_job_cpu_bound_macro("randombytes_uint32", 0,
                                      enif_randombytes_uint32),
    erl_nif_dirty_job_cpu_bound_macro("randombytes_uniform", 1,
                                      enif_randombytes_uniform),

    erl_nif_dirty_job_cpu_bound_macro("crypto_kx_keypair", 0,
                                      enacl_crypto_kx_keypair),
    erl_nif_dirty_job_cpu_bound_macro("crypto_kx_client_session_keys", 3,
                                      enacl_crypto_kx_client_session_keys),
    erl_nif_dirty_job_cpu_bound_macro("crypto_kx_server_session_keys", 3,
                                      enacl_crypto_kx_server_session_keys),
    {"crypto_kx_PUBLICKEYBYTES", 0, enacl_crypto_kx_PUBLICKEYBYTES},
    {"crypto_kx_SECRETKEYBYTES", 0, enacl_crypto_kx_SECRETKEYBYTES},
    {"crypto_kx_SESSIONKEYBYTES", 0, enacl_crypto_kx_SESSIONKEYBYTES},

    {"scramble_block_16", 2, enif_scramble_block_16},

    {"crypto_aead_chacha20poly1305_ietf_KEYBYTES", 0,
     enacl_crypto_aead_chacha20poly1305_ietf_KEYBYTES},
    {"crypto_aead_chacha20poly1305_ietf_NPUBBYTES", 0,
     enacl_crypto_aead_chacha20poly1305_ietf_NPUBBYTES},
    {"crypto_aead_chacha20poly1305_ietf_ABYTES", 0,
     enacl_crypto_aead_chacha20poly1305_ietf_ABYTES},
    {"crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX", 0,
     enacl_crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX},
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_aead_chacha20poly1305_ietf_encrypt", 4,
        enacl_crypto_aead_chacha20poly1305_ietf_encrypt),
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_aead_chacha20poly1305_ietf_decrypt", 4,
        enacl_crypto_aead_chacha20poly1305_ietf_decrypt),

    {"crypto_aead_xchacha20poly1305_ietf_KEYBYTES", 0,
     enacl_crypto_aead_xchacha20poly1305_ietf_KEYBYTES},
    {"crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", 0,
     enacl_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES},
    {"crypto_aead_xchacha20poly1305_ietf_ABYTES", 0,
     enacl_crypto_aead_xchacha20poly1305_ietf_ABYTES},
    {"crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX", 0,
     enacl_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX},
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_aead_xchacha20poly1305_ietf_encrypt", 4,
        enacl_crypto_aead_xchacha20poly1305_ietf_encrypt),
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_aead_xchacha20poly1305_ietf_decrypt", 4,
        enacl_crypto_aead_xchacha20poly1305_ietf_decrypt),

    {"crypto_generichash_BYTES", 0, enacl_crypto_generichash_BYTES},
    {"crypto_generichash_BYTES_MIN", 0, enacl_crypto_generichash_BYTES_MIN},
    {"crypto_generichash_BYTES_MAX", 0, enacl_crypto_generichash_BYTES_MAX},
    {"crypto_generichash_KEYBYTES", 0, enacl_crypto_generichash_KEYBYTES},
    {"crypto_generichash_KEYBYTES_MIN", 0,
     enacl_crypto_generichash_KEYBYTES_MIN},
    {"crypto_generichash_KEYBYTES_MAX", 0,
     enacl_crypto_generichash_KEYBYTES_MAX},
    {"crypto_generichash", 3, enacl_crypto_generichash},
    {"crypto_generichash_init", 2, enacl_crypto_generichash_init},
    erl_nif_dirty_job_cpu_bound_macro("crypto_generichash_update", 2,
                                      enacl_crypto_generichash_update),
    erl_nif_dirty_job_cpu_bound_macro("crypto_generichash_final", 1,
                                      enacl_crypto_generichash_final),

    {"crypto_secretstream_xchacha20poly1305_ABYTES", 0,
     enacl_crypto_secretstream_xchacha20poly1305_ABYTES},
    {"crypto_secretstream_xchacha20poly1305_HEADERBYTES", 0,
     enacl_crypto_secretstream_xchacha20poly1305_HEADERBYTES},
    {"crypto_secretstream_xchacha20poly1305_KEYBYTES", 0,
     enacl_crypto_secretstream_xchacha20poly1305_KEYBYTES},
    {"crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX", 0,
     enacl_crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX},
    {"crypto_secretstream_xchacha20poly1305_TAG_MESSAGE", 0,
     enacl_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE},
    {"crypto_secretstream_xchacha20poly1305_TAG_PUSH", 0,
     enacl_crypto_secretstream_xchacha20poly1305_TAG_PUSH},
    {"crypto_secretstream_xchacha20poly1305_TAG_REKEY", 0,
     enacl_crypto_secretstream_xchacha20poly1305_TAG_REKEY},
    {"crypto_secretstream_xchacha20poly1305_TAG_FINAL", 0,
     enacl_crypto_secretstream_xchacha20poly1305_TAG_FINAL},
    {"crypto_secretstream_xchacha20poly1305_keygen", 0,
     enacl_crypto_secretstream_xchacha20poly1305_keygen},
    {"crypto_secretstream_xchacha20poly1305_init_push", 1,
     enacl_crypto_secretstream_xchacha20poly1305_init_push},
    {"crypto_secretstream_xchacha20poly1305_init_pull", 2,
     enacl_crypto_secretstream_xchacha20poly1305_init_pull},
    {"crypto_secretstream_xchacha20poly1305_rekey", 1,
     enacl_crypto_secretstream_xchacha20poly1305_rekey},
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_secretstream_xchacha20poly1305_push", 4,
        enacl_crypto_secretstream_xchacha20poly1305_push),
    erl_nif_dirty_job_cpu_bound_macro(
        "crypto_secretstream_xchacha20poly1305_pull", 3,
        enacl_crypto_secretstream_xchacha20poly1305_pull)};

ERL_NIF_INIT(enacl_nif, nif_funcs, enacl_crypto_load, NULL, NULL, NULL);
