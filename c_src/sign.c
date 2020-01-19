#include "erl_nif.h"

#include <sodium.h>

#include "enacl.h"
#include "sign.h"

typedef struct enacl_sign_ctx {
  crypto_sign_state *state; // The underlying signature state
  int alive; // Is the context still valid for updates/finalization
} enacl_sign_ctx;

static ErlNifResourceType *enacl_sign_ctx_rtype = NULL;

static void enacl_sign_ctx_dtor(ErlNifEnv *env, enacl_sign_ctx *);

int enacl_init_sign_ctx(ErlNifEnv *env) {
  enacl_sign_ctx_rtype =
      enif_open_resource_type(env, NULL, "enacl_sign_context",
                              (ErlNifResourceDtor *)enacl_sign_ctx_dtor,
                              ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);

  if (enacl_sign_ctx_rtype == NULL)
    return 0;

  return 1;
}

static void enacl_sign_ctx_dtor(ErlNifEnv *env, enacl_sign_ctx *obj) {
  if (!obj->alive)
    return;

  if (obj->state) {
    sodium_memzero(obj->state, crypto_sign_statebytes());
    enif_free(obj->state);
  }

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
    ret = nacl_error_tuple(env, "alloc_failed");
    goto done;
  }
  obj->alive = 0;
  obj->state = enif_alloc(crypto_sign_statebytes());
  if (obj->state == NULL) {
    ret = nacl_error_tuple(env, "state_malloc");
    goto release;
  }
  obj->alive = 1;

  if (0 != crypto_sign_init(obj->state)) {
    ret = nacl_error_tuple(env, "sign_init_error");
    goto free;
  }

  // Create return values
  ret = enif_make_resource(env, obj);

  goto release;

bad_arg:
  return enif_make_badarg(env);
free:
  if (obj->alive)
    if (obj->state != NULL) {
      sodium_memzero(obj->state, crypto_sign_statebytes());
      enif_free(obj->state);
      obj->state = NULL;
    }
release:
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

  if (!obj->alive) {
    ret = nacl_error_tuple(env, "finalized");
    goto done;
  }

  if (0 != crypto_sign_update(obj->state, data.data, data.size)) {
    ret = nacl_error_tuple(env, "sign_update_error");
    goto done;
  }

  ret = argv[0];
  goto done;

bad_arg:
  return enif_make_badarg(env);
done:
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

  if (!obj->alive) {
    ret = nacl_error_tuple(env, "finalized");
    goto done;
  }

  if (!enif_alloc_binary(crypto_sign_BYTES, &sig)) {
    ret = nacl_error_tuple(env, "alloc_failed");
    goto done;
  }

  if (0 != crypto_sign_final_create(obj->state, sig.data, &siglen, sk.data)) {
    ret = nacl_error_tuple(env, "sign_error");
    goto release;
  }

  ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
  ERL_NIF_TERM signature = enif_make_binary(env, &sig);

  ret = enif_make_tuple2(env, ok, signature);
  goto cleanup;
bad_arg:
  return enif_make_badarg(env);
release:
  enif_release_binary(&sig);
cleanup:
  obj->alive = 0;
  sodium_memzero(obj->state, crypto_sign_statebytes());
  enif_free(obj->state);
  obj->state = NULL;
done:
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

  if (0 == crypto_sign_final_verify(obj->state, sig.data, pk.data)) {
    ret = enif_make_atom(env, ATOM_OK);
  } else {
    ret = nacl_error_tuple(env, "failed_verification");
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

  return ret;
}
