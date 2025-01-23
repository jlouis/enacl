#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "sign.h"

typedef struct enacl_sign_ctx {
  ErlNifMutex *mtx;
  crypto_sign_state *state; // The underlying signature state
  int alive; // Is the context still valid for updates/finalization
} enacl_sign_ctx;

ErlNifResourceType *enacl_sign_ctx_rtype = NULL;

void enacl_sign_ctx_dtor(ErlNifEnv *env, enacl_sign_ctx *);

int enacl_init_sign_ctx(ErlNifEnv *env) {
  enacl_sign_ctx_rtype =
      enif_open_resource_type(env, NULL, "enacl_sign_context",
                              (ErlNifResourceDtor *)enacl_sign_ctx_dtor,
                              ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);

  if (enacl_sign_ctx_rtype == NULL)
    return 0;

  return 1;
}

void enacl_sign_ctx_dtor(ErlNifEnv *env, enacl_sign_ctx *obj) {
  if (!obj->alive)
    return;

  if (obj->state) {
    sodium_memzero(obj->state, crypto_sign_statebytes());
    enif_free(obj->state);
  }

  if (obj->mtx != NULL)
    enif_mutex_destroy(obj->mtx);

  return;
}

/*
  int crypto_sign_init(crypto_sign_state *state)
 */

ERL_NIF_TERM enacl_crypto_sign_init(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM ret;
  enacl_sign_ctx *obj = NULL;

  if (argc != 0)
    goto bad_arg;

  if ((obj = enif_alloc_resource(enacl_sign_ctx_rtype,
                                 sizeof(enacl_sign_ctx))) == NULL) {
    ret = enacl_internal_error(env);
    goto done;
  }
  obj->alive = 0;
  obj->state = enif_alloc(crypto_sign_statebytes());
  if (obj->state == NULL) {
    ret = enacl_internal_error(env);
    goto release;
  }
  obj->alive = 1;

  if ((obj->mtx = enif_mutex_create("enacl.sign")) == NULL) {
    goto free;
  }

  if (0 != crypto_sign_init(obj->state)) {
    goto free;
  }

  // Create return values
  ret = enif_make_resource(env, obj);

  goto release;

bad_arg:
  return enif_make_badarg(env);
free:
  ret = enacl_internal_error(env);
  if (obj->alive)
    if (obj->state != NULL) {
      sodium_memzero(obj->state, crypto_sign_statebytes());
      enif_free(obj->state);
      obj->state = NULL;
    }
release:
  // This also frees the mutex via the destructor
  enif_release_resource(obj);
done:
  return ret;
}

/*
  int crypto_sign_update(crypto_sign_state *state,
                        const unsigned char *m,
                        unsigned long long mlen);
 */

ERL_NIF_TERM enacl_crypto_sign_update(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM ret;
  enacl_sign_ctx *obj = NULL;
  ErlNifBinary data;

  // Validate the arguments
  if (argc != 2)
    goto bad_arg;
  if (!enif_get_resource(env, argv[0], enacl_sign_ctx_rtype, (void **)&obj))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &data))
    goto bad_arg;

  enif_mutex_lock(obj->mtx);
  if (!obj->alive) {
    ret = enacl_error_finalized(env);
    goto done;
  }

  if (0 != crypto_sign_update(obj->state, data.data, data.size)) {
    ret = enacl_internal_error(env); // This should never be hit
    goto done;
  }

  ret = argv[0];
  goto done;

bad_arg:
  return enif_make_badarg(env);
done:
  enif_mutex_unlock(obj->mtx);
  return ret;
}

ERL_NIF_TERM enacl_crypto_sign_final_create(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM ret;
  enacl_sign_ctx *obj = NULL;
  ErlNifBinary sk, sig;
  unsigned long long siglen;

  if (argc != 2)
    goto bad_arg;
  if (!enif_get_resource(env, argv[0], enacl_sign_ctx_rtype, (void **)&obj))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &sk))
    goto bad_arg;
  if (sk.size != crypto_sign_SECRETKEYBYTES)
    goto bad_arg;

  enif_mutex_lock(obj->mtx);
  if (!obj->alive) {
    ret = enacl_error_finalized(env);
    goto done;
  }

  if (!enif_alloc_binary(crypto_sign_BYTES, &sig)) {
    ret = enacl_internal_error(env);
    goto done;
  }

  crypto_sign_final_create(obj->state, sig.data, &siglen, sk.data);

  ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM signature = enif_make_binary(env, &sig);

  ret = enif_make_tuple2(env, ok, signature);
  goto cleanup;

bad_arg:
  return enif_make_badarg(env);
cleanup:
  obj->alive = 0;
  sodium_memzero(obj->state, crypto_sign_statebytes());
  enif_free(obj->state);
  obj->state = NULL;
done:
  enif_mutex_unlock(obj->mtx);
  return ret;
}

ERL_NIF_TERM enacl_crypto_sign_final_verify(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sig;
  enacl_sign_ctx *obj = NULL;
  ERL_NIF_TERM ret;

  if (argc != 3)
    goto bad_arg;
  if (!enif_get_resource(env, argv[0], enacl_sign_ctx_rtype, (void **)&obj))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &sig))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[2], &pk))
    goto bad_arg;
  if (pk.size != crypto_sign_PUBLICKEYBYTES)
    goto bad_arg;

  enif_mutex_lock(obj->mtx);
  if (!obj->alive) {
    ret = enacl_error_finalized(env);
    goto done;
  }

  if (0 == crypto_sign_final_verify(obj->state, sig.data, pk.data)) {
    ret = enif_make_atom(env, "true");
  } else {
    ret = enif_make_atom(env, "false");
  }
  // Mark as done
  goto cleanup;

bad_arg:
  return enif_make_badarg(env);
cleanup:
  // Get rid of the context and mark it as dead
  obj->alive = 0;
  sodium_memzero(obj->state, crypto_sign_statebytes());
  enif_free(obj->state);
  obj->state = NULL;
done:
  enif_mutex_unlock(obj->mtx);
  return ret;
}

/* Ed 25519 */
ERL_NIF_TERM
enacl_crypto_sign_ed25519_keypair(ErlNifEnv *env, int argc,
                                  ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_ed25519_PUBLICKEYBYTES, &pk)) {
    return enacl_internal_error(env);
  }

  if (!enif_alloc_binary(crypto_sign_ed25519_SECRETKEYBYTES, &sk)) {
    enif_release_binary(&pk);
    return enacl_internal_error(env);
  }

  crypto_sign_ed25519_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

ERL_NIF_TERM
enacl_crypto_sign_ed25519_sk_to_pk(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &sk)) ||
      (sk.size != crypto_sign_ed25519_SECRETKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_ed25519_PUBLICKEYBYTES, &pk)) {
    return enacl_internal_error(env);
  }

  crypto_sign_ed25519_sk_to_pk(pk.data, sk.data);

  return enif_make_binary(env, &pk);
}

ERL_NIF_TERM
enacl_crypto_sign_ed25519_public_to_curve25519(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]) {
  ErlNifBinary curve25519_pk, ed25519_pk;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &ed25519_pk)) ||
      (ed25519_pk.size != crypto_sign_ed25519_PUBLICKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &curve25519_pk)) {
    return enacl_internal_error(env);
  }

  if (crypto_sign_ed25519_pk_to_curve25519(curve25519_pk.data, ed25519_pk.data) != 0) {
    return enacl_internal_error(env);
  }

  return enif_make_binary(env, &curve25519_pk);
}

ERL_NIF_TERM
enacl_crypto_sign_ed25519_secret_to_curve25519(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]) {
  ErlNifBinary curve25519_sk, ed25519_sk;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &ed25519_sk)) ||
      (ed25519_sk.size != crypto_sign_ed25519_SECRETKEYBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &curve25519_sk)) {
    return enacl_internal_error(env);
  }

  crypto_sign_ed25519_sk_to_curve25519(curve25519_sk.data, ed25519_sk.data);

  return enif_make_binary(env, &curve25519_sk);
}

ERL_NIF_TERM
enacl_crypto_sign_ed25519_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_ed25519_PUBLICKEYBYTES);
}

ERL_NIF_TERM
enacl_crypto_sign_ed25519_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_ed25519_SECRETKEYBYTES);
}

ERL_NIF_TERM enacl_crypto_sign_PUBLICKEYBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_PUBLICKEYBYTES);
}

ERL_NIF_TERM enacl_crypto_sign_SECRETKEYBYTES(ErlNifEnv *env, int argc,
                                              ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_SECRETKEYBYTES);
}

ERL_NIF_TERM enacl_crypto_sign_SEEDBYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_sign_SEEDBYTES);
}

ERL_NIF_TERM enacl_crypto_sign_keypair(ErlNifEnv *env, int argc,
                                       ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_PUBLICKEYBYTES, &pk)) {
    return enacl_internal_error(env);
  }

  if (!enif_alloc_binary(crypto_sign_SECRETKEYBYTES, &sk)) {
    enif_release_binary(&pk);
    return enacl_internal_error(env);
  }

  crypto_sign_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

ERL_NIF_TERM enacl_crypto_sign_seed_keypair(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  ErlNifBinary pk, sk, seed;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &seed))) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_sign_PUBLICKEYBYTES, &pk)) {
    return enacl_internal_error(env);
  }

  if (!enif_alloc_binary(crypto_sign_SECRETKEYBYTES, &sk)) {
    enif_release_binary(&pk);
    return enacl_internal_error(env);
  }

  crypto_sign_seed_keypair(pk.data, sk.data, seed.data);

  return enif_make_tuple2(env, enif_make_binary(env, &pk),
                          enif_make_binary(env, &sk));
}

ERL_NIF_TERM enacl_crypto_sign(ErlNifEnv *env, int argc,
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
    return enacl_internal_error(env);
  }

  crypto_sign(sm.data, &smlen, m.data, m.size, sk.data);

  return enif_make_sub_binary(env, enif_make_binary(env, &sm), 0, smlen);
}

ERL_NIF_TERM enacl_crypto_sign_open(ErlNifEnv *env, int argc,
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
    return enacl_internal_error(env);
  }

  if (0 == crypto_sign_open(m.data, &mlen, sm.data, sm.size, pk.data)) {
    ERL_NIF_TERM ret_ok = enif_make_atom(env, ATOM_OK);
    ERL_NIF_TERM ret_bin =
        enif_make_sub_binary(env, enif_make_binary(env, &m), 0, mlen);
    return enif_make_tuple2(env, ret_ok, ret_bin);
  } else {
    enif_release_binary(&m);
    return enacl_error_tuple(env, "failed_verification");
  }
}

ERL_NIF_TERM enacl_crypto_sign_detached(ErlNifEnv *env, int argc,
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
    return enacl_internal_error(env);
  }

  crypto_sign_detached(sig.data, &siglen, m.data, m.size, sk.data);

  return enif_make_binary(env, &sig);
}

ERL_NIF_TERM
enacl_crypto_sign_verify_detached(ErlNifEnv *env, int argc,
                                  ERL_NIF_TERM const argv[]) {
  ErlNifBinary m, sig, pk;

  if ((argc != 3) || (!enif_inspect_binary(env, argv[0], &sig)) ||
      (!enif_inspect_iolist_as_binary(env, argv[1], &m)) ||
      (!enif_inspect_binary(env, argv[2], &pk))) {
    return enif_make_badarg(env);
  }

  if (sig.size != crypto_sign_BYTES) {
    return enif_make_badarg(env);
  }

  if (pk.size != crypto_sign_PUBLICKEYBYTES) {
    return enif_make_badarg(env);
  }

  if (0 == crypto_sign_verify_detached(sig.data, m.data, m.size, pk.data)) {
    return enif_make_atom(env, ATOM_TRUE);
  } else {
    return enif_make_atom(env, ATOM_FALSE);
  }
}
