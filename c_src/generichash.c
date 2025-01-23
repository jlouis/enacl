#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "generichash.h"

typedef struct enacl_generichash_ctx {
  ErlNifMutex *mtx;
  crypto_generichash_state *ctx; // Underlying hash state from sodium
  int alive;  // Is the context still valid for updates/finalizes?
  int outlen; // Final size of the hash

} enacl_generichash_ctx;

static ErlNifResourceType *enacl_generic_hash_ctx_rtype;

static void enacl_generic_hash_ctx_dtor(ErlNifEnv *env,
                                        enacl_generichash_ctx *);

int enacl_init_generic_hash_ctx(ErlNifEnv *env) {
  enacl_generic_hash_ctx_rtype =
      enif_open_resource_type(env, NULL, "enacl_generichash_context",
                              (ErlNifResourceDtor *)enacl_generic_hash_ctx_dtor,
                              ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);

  if (enacl_generic_hash_ctx_rtype == NULL)
    return 0;

  return 1;
}

static void enacl_generic_hash_ctx_dtor(ErlNifEnv *env,
                                        enacl_generichash_ctx *obj) {
  if (!obj->alive) {
    return;
  }

  if (obj->ctx)
    sodium_free(obj->ctx);

  if (obj->mtx != NULL)
    enif_mutex_destroy(obj->mtx);

  return;
}

/*
 * Generic hash
 */
ERL_NIF_TERM enacl_crypto_generichash_BYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_generichash_BYTES);
}

ERL_NIF_TERM enacl_crypto_generichash_BYTES_MIN(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_generichash_BYTES_MIN);
}

ERL_NIF_TERM enacl_crypto_generichash_BYTES_MAX(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_generichash_BYTES_MAX);
}

ERL_NIF_TERM enacl_crypto_generichash_KEYBYTES(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_generichash_KEYBYTES);
}

ERL_NIF_TERM enacl_crypto_generichash_KEYBYTES_MIN(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_generichash_KEYBYTES_MIN);
}

ERL_NIF_TERM enacl_crypto_generichash_KEYBYTES_MAX(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_generichash_KEYBYTES_MAX);
}

ERL_NIF_TERM enacl_crypto_generichash(ErlNifEnv *env, int argc,
                                      ERL_NIF_TERM const argv[]) {
  ErlNifBinary hash, message, key;
  unsigned hash_size;
  ERL_NIF_TERM ret;

  // Validate the arguments
  if (argc != 3)
    goto bad_arg;
  if (!enif_get_uint(env, argv[0], &hash_size))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &message))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[2], &key))
    goto bad_arg;

  // Verify that hash size is
  // crypto_generichash_BYTES/crypto_generichash_BYTES_MIN/crypto_generichash_BYTES_MAX
  if ((hash_size < crypto_generichash_BYTES_MIN) ||
      (hash_size > crypto_generichash_BYTES_MAX)) {
    goto bad_arg;
  }

  // validate key size
  unsigned char *k = key.data;
  if (0 == key.size) {
    k = NULL;
  } else if (key.size < crypto_generichash_KEYBYTES_MIN ||
             key.size > crypto_generichash_KEYBYTES_MAX) {
    goto bad_arg;
  }

  // allocate memory for hash
  if (!enif_alloc_binary(hash_size, &hash)) {
    goto err;
  }

  // calculate hash
  if (0 != crypto_generichash(hash.data, hash.size, message.data, message.size,
                              k, key.size)) {
    goto release;
  }

  ret = enif_make_binary(env, &hash);
  goto done;

bad_arg:
  return enif_make_badarg(env);
release:
  enif_release_binary(&hash);
err:
  ret = enacl_internal_error(env);
done:
  return ret;
}

ERL_NIF_TERM enacl_crypto_generichash_init(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  ErlNifBinary key;
  unsigned hash_size;
  enacl_generichash_ctx *obj = NULL;
  ERL_NIF_TERM ret;

  // Validate the arguments
  if (argc != 2)
    goto bad_arg;
  if (!enif_get_uint(env, argv[0], &hash_size))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &key))
    goto bad_arg;

  // Verify that hash size is valid
  if ((hash_size < crypto_generichash_BYTES_MIN) ||
      (hash_size > crypto_generichash_BYTES_MAX)) {
    goto bad_arg;
  }

  // validate key size
  unsigned char *k = key.data;
  if (0 == key.size) {
    k = NULL;
  } else if (key.size < crypto_generichash_KEYBYTES_MIN ||
             key.size > crypto_generichash_KEYBYTES_MAX) {
    goto bad_arg;
  }

  // Create the resource
  if ((obj = enif_alloc_resource(enacl_generic_hash_ctx_rtype,
                                 sizeof(enacl_generichash_ctx))) == NULL) {
    goto err;
  }

  // Allocate the state context via libsodium
  // Note that this ensures a 64byte alignment for the resource
  // And also protects the resource via guardpages
  obj->mtx = NULL;
  obj->ctx = NULL;
  obj->alive = 0;
  obj->outlen = 0;

  obj->ctx = (crypto_generichash_state *)sodium_malloc(
      crypto_generichash_statebytes());
  if (obj->ctx == NULL) {
    goto err;
  }
  obj->alive = 1;
  obj->outlen = hash_size;

  if ((obj->mtx = enif_mutex_create("enacl.generichash")) == NULL) {
    ret = enacl_error_tuple(env, "mutex_create");
    goto err;
  }

  // Call the library function
  if (0 != crypto_generichash_init(obj->ctx, k, key.size, obj->outlen)) {
    ret = enacl_error_tuple(env, "hash_init_error");
    goto err;
  }

  ret = enif_make_resource(env, obj);
  goto done;

bad_arg:
  return enif_make_badarg(env);
err:
  ret = enacl_internal_error(env);
  if (obj != NULL) {
    if (obj->alive) {
      sodium_free(obj->ctx);
      obj->alive = 0; // Maintain the invariant consistently
    }
  }
done:
  if (obj != NULL) {
    enif_release_resource(obj);
  }
  return ret;
}

ERL_NIF_TERM enacl_crypto_generichash_update(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM ret;
  ErlNifBinary data;
  enacl_generichash_ctx *obj = NULL;

  // Validate the arguments
  if (argc != 2)
    goto bad_arg;
  if (!enif_get_resource(env, argv[0],
                         (ErlNifResourceType *)enacl_generic_hash_ctx_rtype,
                         (void **)&obj))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &data))
    goto bad_arg;

  enif_mutex_lock(obj->mtx);
  if (!obj->alive) {
    goto err;
  }

  // Update hash state
  if (0 != crypto_generichash_update(obj->ctx, data.data, data.size)) {
    goto err;
  }

  ret = argv[0];
  goto done;

bad_arg:
  return enif_make_badarg(env);
err:
  ret = enacl_error_finalized(env);
done:
  enif_mutex_unlock(obj->mtx);
  return ret;
}

ERL_NIF_TERM enacl_crypto_generichash_final(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM ret;
  ErlNifBinary hash;
  enacl_generichash_ctx *obj = NULL;

  if (argc != 1)
    goto bad_arg;
  if (!enif_get_resource(env, argv[0], enacl_generic_hash_ctx_rtype,
                         (void **)&obj))
    goto bad_arg;

  enif_mutex_lock(obj->mtx);
  if (!obj->alive) {
    ret = enacl_error_finalized(env);
    goto done;
  }

  if (!enif_alloc_binary(obj->outlen, &hash)) {
    goto err;
  }

  if (0 != crypto_generichash_final(obj->ctx, hash.data, hash.size)) {
    goto release;
  }

  // Finalize the object such that it cannot be reused by accident
  if (obj->ctx)
    sodium_free(obj->ctx);
  obj->alive = 0;

  ret = enif_make_binary(env, &hash);
  goto done;

bad_arg:
  return enif_make_badarg(env);
release:
  enif_release_binary(&hash);
err:
  ret = enacl_internal_error(env);
done:
  enif_mutex_unlock(obj->mtx);
  return ret;
}
