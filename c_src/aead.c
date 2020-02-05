#include <sodium.h>

#include <erl_nif.h>

#include "aead.h"
#include "enacl.h"

/*
 * AEAD ChaCha20 Poly1305
 */
ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_KEYBYTES(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
}

ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_NPUBBYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}

ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_ABYTES(ErlNifEnv *env, int argc,
                                               ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_chacha20poly1305_ietf_ABYTES);
}

ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX(
    ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env,
                         crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX);
}

ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_encrypt(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM ret;
  ErlNifBinary key, nonce, ad, message, ciphertext;

  if (argc != 4)
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[0], &message))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &ad))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[2], &nonce))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[3], &key))
    goto bad_arg;
  if (key.size != crypto_aead_chacha20poly1305_ietf_KEYBYTES)
    goto bad_arg;
  if (nonce.size != crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
    goto bad_arg;

  if (!enif_alloc_binary(message.size +
                             crypto_aead_chacha20poly1305_ietf_ABYTES,
                         &ciphertext)) {
    goto err;
  }

  crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext.data, NULL, message.data,
                                            message.size, ad.data, ad.size,
                                            NULL, nonce.data, key.data);

  ret = enif_make_binary(env, &ciphertext);
  goto done;

bad_arg:
  return enif_make_badarg(env);
err:
  ret = enacl_internal_error(env);
done:
  return ret;
}

ERL_NIF_TERM
enacl_crypto_aead_chacha20poly1305_ietf_decrypt(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM ret;
  ErlNifBinary key, nonce, ad, message, ciphertext;

  if (argc != 4)
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[0], &ciphertext))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &ad))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[2], &nonce))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[3], &key))
    goto bad_arg;

  if (ciphertext.size < crypto_aead_chacha20poly1305_ietf_ABYTES)
    goto bad_arg;
  if (key.size != crypto_aead_chacha20poly1305_ietf_KEYBYTES)
    goto bad_arg;
  if (nonce.size != crypto_aead_chacha20poly1305_ietf_NPUBBYTES)
    goto bad_arg;

  if (!enif_alloc_binary(ciphertext.size -
                             crypto_aead_chacha20poly1305_ietf_ABYTES,
                         &message)) {
    return enacl_internal_error(env);
  }

  if (crypto_aead_chacha20poly1305_ietf_decrypt(
          message.data, NULL, NULL, ciphertext.data, ciphertext.size, ad.data,
          ad.size, nonce.data, key.data) != 0) {
    ret = enacl_error_tuple(env, "failed_verification");
    goto release;
  }

  ret = enif_make_binary(env, &message);
  goto done;
bad_arg:
  return enif_make_badarg(env);
release:
  enif_release_binary(&message);
done:
  return ret;
}

/*
 * AEAD XChaCha20 Poly1305
 */
ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_KEYBYTES(ErlNifEnv *env, int argc,
                                                  ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_ABYTES(ErlNifEnv *env, int argc,
                                                ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_ABYTES);
}

ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX(
    ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env,
                         crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX);
}

ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_encrypt(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, nonce, ad, message, ciphertext;
  ERL_NIF_TERM ret;

  if (argc != 4)
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[0], &message))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &ad))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[2], &nonce))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[3], &key))
    goto bad_arg;

  if (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    goto bad_arg;
  if (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    goto bad_arg;

  if (!enif_alloc_binary(message.size +
                             crypto_aead_xchacha20poly1305_ietf_ABYTES,
                         &ciphertext)) {
    goto err;
  }

  crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext.data, NULL, message.data, message.size, ad.data, ad.size, NULL,
      nonce.data, key.data);

  ret = enif_make_binary(env, &ciphertext);
  goto done;

bad_arg:
  return enif_make_badarg(env);
err:
  ret = enacl_internal_error(env);
done:
  return ret;
}

ERL_NIF_TERM
enacl_crypto_aead_xchacha20poly1305_ietf_decrypt(ErlNifEnv *env, int argc,
                                                 ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, nonce, ad, message, ciphertext;
  ERL_NIF_TERM ret;

  if (argc != 4)
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[0], &ciphertext))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[1], &ad))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[2], &nonce))
    goto bad_arg;
  if (!enif_inspect_binary(env, argv[3], &key))
    goto bad_arg;

  if (ciphertext.size < crypto_aead_xchacha20poly1305_ietf_ABYTES)
    goto bad_arg;
  if (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    goto bad_arg;
  if (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    goto bad_arg;

  if (!enif_alloc_binary(ciphertext.size -
                             crypto_aead_xchacha20poly1305_ietf_ABYTES,
                         &message)) {
    return enacl_internal_error(env);
  }

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          message.data, NULL, NULL, ciphertext.data, ciphertext.size, ad.data,
          ad.size, nonce.data, key.data) != 0) {
    ret = enacl_error_tuple(env, "failed_verification");
    goto release;
  }

  ret = enif_make_binary(env, &message);
  goto done;

bad_arg:
  return enif_make_badarg(env);
release:
  enif_release_binary(&message);
done:
  return ret;
}
