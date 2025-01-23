#include <erl_nif.h>
#include <sodium.h>

#include "enacl.h"
#include "secretstream.h"

typedef struct enacl_secretstream_ctx {
  ErlNifMutex *mtx;
  crypto_secretstream_xchacha20poly1305_state
      *state; // The underlying secretstream state
  int alive;  // Is the context still valid for updates/finalization
} enacl_secretstream_ctx;

ErlNifResourceType *enacl_secretstream_ctx_rtype = NULL;

static void enacl_secretstream_ctx_dtor(ErlNifEnv *env,
                                        enacl_secretstream_ctx *);

int enacl_init_secretstream_ctx(ErlNifEnv *env) {
  enacl_secretstream_ctx_rtype =
      enif_open_resource_type(env, NULL, "enacl_secretstream_context",
                              (ErlNifResourceDtor *)enacl_secretstream_ctx_dtor,
                              ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);

  if (enacl_secretstream_ctx_rtype == NULL)
    return 0;

  return 1;
}

static void enacl_secretstream_ctx_dtor(ErlNifEnv *env,
                                        enacl_secretstream_ctx *obj) {
  if (!obj->alive) {
    return;
  }

  if (obj->state)
    sodium_memzero(obj->state,
                   crypto_secretstream_xchacha20poly1305_statebytes());
  enif_free(obj->state);

  if (obj->mtx != NULL)
    enif_mutex_destroy(obj->mtx);

  return;
}

/*
 * Secretstream
 */

ERL_NIF_TERM
enacl_crypto_secretstream_xchacha20poly1305_ABYTES(ErlNifEnv *env, int argc,
                                                   const ERL_NIF_TERM argv[]) {
  return enif_make_int64(env, crypto_secretstream_xchacha20poly1305_ABYTES);
}

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_HEADERBYTES(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  return enif_make_int64(env,
                         crypto_secretstream_xchacha20poly1305_HEADERBYTES);
}

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_KEYBYTES(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  return enif_make_int64(env, crypto_secretstream_xchacha20poly1305_KEYBYTES);
}

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  return enif_make_int64(
      env, crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX);
}

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {

  return enif_make_int64(env,
                         crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
}

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_TAG_PUSH(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {

  return enif_make_int64(env, crypto_secretstream_xchacha20poly1305_TAG_PUSH);
}

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_TAG_REKEY(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {

  return enif_make_int64(env, crypto_secretstream_xchacha20poly1305_TAG_REKEY);
}

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_TAG_FINAL(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {

  return enif_make_int64(env, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
}

ERL_NIF_TERM
enacl_crypto_secretstream_xchacha20poly1305_keygen(ErlNifEnv *env, int argc,
                                                   const ERL_NIF_TERM argv[]) {

  ErlNifBinary key;

  if (argc != 0) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(crypto_secretstream_xchacha20poly1305_KEYBYTES,
                         &key)) {
    return enacl_internal_error(env);
  }

  crypto_secretstream_xchacha20poly1305_keygen(key.data);

  return enif_make_binary(env, &key);
}

/*
   int crypto_secretstream_xchacha20poly1305_init_push
      (crypto_secretstream_xchacha20poly1305_state *state,
      unsigned char out[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
      const unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES])
*/
ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_init_push(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  ERL_NIF_TERM ret;
  ErlNifBinary key, header;
  enacl_secretstream_ctx *obj = NULL;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &key))) {
    goto bad_arg;
  }

  if (key.size != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
    goto bad_arg;
  }

  if (!enif_alloc_binary(crypto_secretstream_xchacha20poly1305_HEADERBYTES,
                         &header)) {
    ret = enacl_internal_error(env);
    goto done;
  }

  if ((obj = enif_alloc_resource(enacl_secretstream_ctx_rtype,
                                 sizeof(enacl_secretstream_ctx))) == NULL) {
    ret = enacl_internal_error(env);
    goto release_header;
  }
  obj->alive = 0;
  obj->state = enif_alloc(crypto_secretstream_xchacha20poly1305_statebytes());

  if (obj->state == NULL) {
    ret = enacl_internal_error(env);
    goto release;
  }
  obj->alive = 1;

  if ((obj->mtx = enif_mutex_create("enacl.secretstream")) == NULL) {
    ret = enacl_internal_error(env);
    goto free;
  }

  crypto_secretstream_xchacha20poly1305_init_push(obj->state, header.data,
                                                  key.data);

  ret = enif_make_tuple2(env, enif_make_binary(env, &header),
                         enif_make_resource(env, obj));

  goto release;
bad_arg:
  return enif_make_badarg(env);
free:
  if (obj->alive)
    if (obj->state != NULL) {
      sodium_memzero(obj->state,
                     crypto_secretstream_xchacha20poly1305_statebytes());
      enif_free(obj->state);
      obj->state = NULL;
    }
release_header:
  enif_release_binary(&header);
release:
  // This also frees the mutex via the destructor
  enif_release_resource(obj);
done:
  return ret;
}

/*
crypto_secretstream_xchacha20poly1305_init_pull
   (crypto_secretstream_xchacha20poly1305_state *state,
    const unsigned char in[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES])
*/
ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_init_pull(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  ERL_NIF_TERM ret;
  ErlNifBinary header, key;
  enacl_secretstream_ctx *obj = NULL;

  if (argc != 2) {
    goto bad_arg;
  }

  if (!enif_inspect_binary(env, argv[0], &header)) {
    goto bad_arg;
  }

  if (!enif_inspect_binary(env, argv[1], &key)) {
    goto bad_arg;
  }

  if ((key.size != crypto_secretstream_xchacha20poly1305_KEYBYTES) ||
      (header.size != crypto_secretstream_xchacha20poly1305_HEADERBYTES)) {
    goto bad_arg;
  }

  if ((obj = enif_alloc_resource(enacl_secretstream_ctx_rtype,
                                 sizeof(enacl_secretstream_ctx))) == NULL) {
    ret = enacl_internal_error(env);
    goto done;
  }

  obj->alive = 0;
  obj->state = enif_alloc(crypto_secretstream_xchacha20poly1305_statebytes());

  if (obj->state == NULL) {
    ret = enacl_internal_error(env);
    goto release;
  }
  obj->alive = 1;

  if ((obj->mtx = enif_mutex_create("enacl.secretstream")) == NULL) {
    ret = enacl_internal_error(env);
    goto free;
  }

  crypto_secretstream_xchacha20poly1305_init_pull(obj->state, header.data,
                                                  key.data);

  ret = enif_make_resource(env, obj);

  goto release;

bad_arg:
  return enif_make_badarg(env);
free:
  if (obj->alive)
    if (obj->state != NULL) {
      sodium_memzero(obj->state,
                     crypto_secretstream_xchacha20poly1305_statebytes());
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
void
crypto_secretstream_xchacha20poly1305_rekey
    (crypto_secretstream_xchacha20poly1305_state *state)
*/
ERL_NIF_TERM
enacl_crypto_secretstream_xchacha20poly1305_rekey(ErlNifEnv *env, int argc,
                                                  const ERL_NIF_TERM argv[]) {
  ERL_NIF_TERM ret;
  enacl_secretstream_ctx *obj = NULL;

  if (argc != 1) {
    goto bad_arg;
  }

  if (!enif_get_resource(env, argv[0],
                         (ErlNifResourceType *)enacl_secretstream_ctx_rtype,
                         (void **)&obj)) {
    goto bad_arg;
  }

  enif_mutex_lock(obj->mtx);
  if (!obj->alive) {
    goto err;
  }

  crypto_secretstream_xchacha20poly1305_rekey(obj->state);

  ret = enif_make_atom(env, ATOM_OK);

  goto done;

bad_arg:
  return enif_make_badarg(env);
err:
  ret = enacl_error_finalized(env);
done:
  enif_mutex_unlock(obj->mtx);
  return ret;
}

/*
int
crypto_secretstream_xchacha20poly1305_push
   (crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char *out, unsigned long long *outlen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen, unsigned char tag)
*/
ERL_NIF_TERM
enacl_crypto_secretstream_xchacha20poly1305_push(ErlNifEnv *env, int argc,
                                                 const ERL_NIF_TERM argv[]) {
  ERL_NIF_TERM ret;
  ErlNifBinary m, ad, out;
  ErlNifUInt64 tag;
  enacl_secretstream_ctx *obj = NULL;

  if (argc != 4) {
    goto bad_arg;
  }

  if (!enif_get_resource(env, argv[0],
                         (ErlNifResourceType *)enacl_secretstream_ctx_rtype,
                         (void **)&obj)) {
    goto bad_arg;
  }

  if (!enif_inspect_binary(env, argv[1], &m)) {
    goto bad_arg;
  }

  if (!enif_inspect_binary(env, argv[2], &ad)) {
    goto bad_arg;
  }

  if (!enif_get_uint64(env, argv[3], &tag)) {
    goto bad_arg;
  }

  if (!enif_alloc_binary(m.size + crypto_secretstream_xchacha20poly1305_ABYTES,
                         &out)) {
    return enacl_internal_error(env);
  }

  enif_mutex_lock(obj->mtx);
  if (!obj->alive) {
    goto err;
  }

  crypto_secretstream_xchacha20poly1305_push(obj->state, out.data, NULL, m.data,
                                             m.size, ad.data, ad.size, tag);

  if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
    if (obj->state) {
      obj->alive = 0;
      sodium_memzero(obj->state,
                     crypto_secretstream_xchacha20poly1305_statebytes());
      enif_free(obj->state);
      obj->state = NULL;
    }
  }

  ret = enif_make_binary(env, &out);

  goto done;

bad_arg:
  return enif_make_badarg(env);
err:
  ret = enacl_error_finalized(env);
  enif_release_binary(&out);
done:
  enif_mutex_unlock(obj->mtx);
  return ret;
}

/*
   crypto_secretstream_xchacha20poly1305_pull
   (crypto_secretstream_xchacha20poly1305_state *state,
   unsigned char *m, unsigned long long *mlen_p, unsigned char *tag_p,
   const unsigned char *in, unsigned long long inlen,
   const unsigned char *ad, unsigned long long adlen)
   */
ERL_NIF_TERM
enacl_crypto_secretstream_xchacha20poly1305_pull(ErlNifEnv *env, int argc,
                                                 const ERL_NIF_TERM argv[]) {
  ERL_NIF_TERM ret;
  ErlNifBinary m, in, ad;
  unsigned char tag;
  enacl_secretstream_ctx *obj = NULL;

  if (argc != 3) {
    goto bad_arg;
  }

  if (!enif_get_resource(env, argv[0],
                         (ErlNifResourceType *)enacl_secretstream_ctx_rtype,
                         (void **)&obj)) {
    goto bad_arg;
  }

  if (!enif_inspect_binary(env, argv[1], &in)) {
    goto bad_arg;
  }

  if (in.size < crypto_secretstream_xchacha20poly1305_ABYTES) {
    goto bad_arg;
  }

  if (!enif_inspect_binary(env, argv[2], &ad)) {
    goto bad_arg;
  }

  if (in.size < crypto_secretstream_xchacha20poly1305_ABYTES) {
    goto bad_arg;
  }

  if (!enif_alloc_binary(in.size - crypto_secretstream_xchacha20poly1305_ABYTES,
                         &m)) {
    return enacl_internal_error(env);
  }

  enif_mutex_lock(obj->mtx);
  if (!obj->alive) {
    goto err;
  }

  if (0 != crypto_secretstream_xchacha20poly1305_pull(obj->state, m.data, NULL,
                                                      &tag, in.data, in.size,
                                                      ad.data, ad.size)) {
    ret = enacl_error_tuple(env, "failed_verification");
    goto release;
  }

  if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
    if (obj->state) {
      obj->alive = 0;
      sodium_memzero(obj->state,
                     crypto_secretstream_xchacha20poly1305_statebytes());
      enif_free(obj->state);
      obj->state = NULL;
    }
  }

  ret = enif_make_tuple2(env, enif_make_binary(env, &m),
                         enif_make_int64(env, tag));

  goto done;

bad_arg:
  return enif_make_badarg(env);
err:
  ret = enacl_error_finalized(env);
release:
  enif_release_binary(&m);
done:
  enif_mutex_unlock(obj->mtx);
  return ret;
}
