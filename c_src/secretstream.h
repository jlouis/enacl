#ifndef ENACL_SECRETSTREAM_H
#define ENACL_SECRETSTREAM_H

#include <erl_nif.h>

int enacl_init_secretstream_ctx(ErlNifEnv *env);

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_ABYTES(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_HEADERBYTES(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_KEYBYTES(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_TAG_MESSAGE(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_TAG_PUSH(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_TAG_REKEY(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_TAG_FINAL(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_keygen(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_init_push(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_init_pull(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_rekey(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_push(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

ERL_NIF_TERM enacl_crypto_secretstream_xchacha20poly1305_pull(
    ErlNifEnv *env, int argc,
    const ERL_NIF_TERM argv[]
    );

#endif
