#include "aead.h"
#include "enacl.h"
#include "erl_nif.h"

#include <sodium.h>

/*
 * AEAD ChaCha20 Poly1305
 */
ERL_NIF_TERM
enif_crypto_aead_chacha20poly1305_KEYBYTES(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
}

ERL_NIF_TERM
enif_crypto_aead_chacha20poly1305_NPUBBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
}

ERL_NIF_TERM
enif_crypto_aead_chacha20poly1305_ABYTES(ErlNifEnv *env, int argc,
                                         ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_chacha20poly1305_ietf_ABYTES);
}

ERL_NIF_TERM
enif_crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX(ErlNifEnv *env, int argc,
                                                   ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env,
                         crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX);
}

ERL_NIF_TERM
enif_crypto_aead_chacha20poly1305_encrypt(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary key, nonce, ad, message, ciphertext;

  if ((argc != 4) || (!enif_inspect_binary(env, argv[0], &key)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &ad)) ||
      (!enif_inspect_binary(env, argv[3], &message)) ||
      (key.size != crypto_aead_chacha20poly1305_ietf_KEYBYTES) ||
      (nonce.size != crypto_aead_chacha20poly1305_ietf_NPUBBYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(message.size +
                               crypto_aead_chacha20poly1305_ietf_ABYTES,
                           &ciphertext)) {
      result = nacl_error_tuple(env, "alloc_failed");
      continue;
    }

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data, NULL, message.data, message.size, ad.data, ad.size,
            NULL, nonce.data, key.data) < 0) {
      result =
          nacl_error_tuple(env, "aead_chacha20poly1305_ietf_encrypt_failed");
      continue;
    }

    result = enif_make_binary(env, &ciphertext);
  } while (0);

  return result;
}

ERL_NIF_TERM
enif_crypto_aead_chacha20poly1305_decrypt(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary key, nonce, ad, message, ciphertext;

  if ((argc != 4) || (!enif_inspect_binary(env, argv[0], &key)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &ad)) ||
      (!enif_inspect_binary(env, argv[3], &ciphertext)) ||
      (ciphertext.size < crypto_aead_chacha20poly1305_ietf_ABYTES) ||
      (key.size != crypto_aead_chacha20poly1305_ietf_KEYBYTES) ||
      (nonce.size != crypto_aead_chacha20poly1305_ietf_NPUBBYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(ciphertext.size -
                               crypto_aead_chacha20poly1305_ietf_ABYTES,
                           &message)) {
      result = nacl_error_tuple(env, "alloc_failed");
      continue;
    }

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            message.data, NULL, NULL, ciphertext.data, ciphertext.size, ad.data,
            ad.size, nonce.data, key.data) < 0) {
      result =
          nacl_error_tuple(env, "aead_chacha20poly1305_ietf_decrypt_failed");
      continue;
    }

    result = enif_make_binary(env, &message);
  } while (0);

  return result;
}

/*
 * AEAD XChaCha20 Poly1305
 */
ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_KEYBYTES(ErlNifEnv *env, int argc,
                                            ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_NPUBBYTES(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_ABYTES(ErlNifEnv *env, int argc,
                                          ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_ABYTES);
}

ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_MESSAGEBYTES_MAX(ErlNifEnv *env, int argc,
                                                    ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env,
                         crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX);
}

ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_encrypt(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, nonce, ad, message, ciphertext;

  if ((argc != 4) || (!enif_inspect_binary(env, argv[0], &key)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &ad)) ||
      (!enif_inspect_binary(env, argv[3], &message)) ||
      (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) ||
      (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(message.size +
                             crypto_aead_xchacha20poly1305_ietf_ABYTES,
                         &ciphertext)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          ciphertext.data, NULL, message.data, message.size, ad.data, ad.size,
          NULL, nonce.data, key.data) < 0) {
    return nacl_error_tuple(env, "aead_xchacha20poly1305_ietf_encrypt_failed");
  }

  return enif_make_binary(env, &ciphertext);
}

ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_decrypt(ErlNifEnv *env, int argc,
                                           ERL_NIF_TERM const argv[]) {
  ErlNifBinary key, nonce, ad, message, ciphertext;

  if ((argc != 4) || (!enif_inspect_binary(env, argv[0], &key)) ||
      (!enif_inspect_binary(env, argv[1], &nonce)) ||
      (!enif_inspect_binary(env, argv[2], &ad)) ||
      (!enif_inspect_binary(env, argv[3], &ciphertext)) ||
      (ciphertext.size < crypto_aead_xchacha20poly1305_ietf_ABYTES) ||
      (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) ||
      (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(ciphertext.size -
                             crypto_aead_xchacha20poly1305_ietf_ABYTES,
                         &message)) {
    return nacl_error_tuple(env, "alloc_failed");
  }

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          message.data, NULL, NULL, ciphertext.data, ciphertext.size, ad.data,
          ad.size, nonce.data, key.data) < 0) {
    return nacl_error_tuple(env, "aead_xchacha20poly1305_ietf_decrypt_failed");
  }

  return enif_make_binary(env, &message);
}
