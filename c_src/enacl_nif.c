#include "erl_nif.h"

#include <sodium.h>

/* Errors */
static
ERL_NIF_TERM nacl_error_tuple(ErlNifEnv *env, char *error_atom) {
	return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error_atom));
}

/* Helper functions (Hashing, String Equality, ...) */

static
ERL_NIF_TERM enif_crypto_hash(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary input;
	ErlNifBinary result;
	
	if ((argc != 1) || (!enif_inspect_iolist_as_binary(env, argv[0], &input))) {
		return enif_make_badarg(env);
	}
	
	if (!enif_alloc_binary(crypto_hash_BYTES, &result)) {
		return nacl_error_tuple(env, "alloc_failed");
	}
	
	crypto_hash(result.data, input.data, input.size);
	
	return enif_make_binary(env, &result);
}

/* Public-key cryptography */
static
ERL_NIF_TERM enif_crypto_box_NONCEBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_box_NONCEBYTES);
}

static
ERL_NIF_TERM enif_crypto_box_ZEROBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_box_ZEROBYTES);
}

static
ERL_NIF_TERM enif_crypto_box_BOXZEROBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_box_BOXZEROBYTES);
}

static
ERL_NIF_TERM enif_crypto_box_PUBLICKEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_box_PUBLICKEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_box_SECRETKEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_box_SECRETKEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_box_keypair(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
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
	
	return enif_make_tuple3(env, enif_make_atom(env, "ok"), enif_make_binary(env, &pk), enif_make_binary(env, &sk));
}

static
ERL_NIF_TERM enif_crypto_box(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary padded_msg, nonce, pk, sk, result;
	
	if (
	  (argc != 4) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &padded_msg)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &nonce)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[2], &pk)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[3], &sk))) {
	  	return enif_make_badarg(env);
	}
	
	if (
	    (nonce.size != crypto_box_NONCEBYTES) ||
	    (pk.size != crypto_box_PUBLICKEYBYTES) ||
	    (sk.size != crypto_box_SECRETKEYBYTES) ||
	    (padded_msg.size < crypto_box_ZEROBYTES)) {
		return enif_make_badarg(env);
	}
	
	if (!enif_alloc_binary(padded_msg.size, &result)) {
		return nacl_error_tuple(env, "alloc_failed");
	}
	
	crypto_box(result.data, padded_msg.data, padded_msg.size, nonce.data, pk.data, sk.data);
	
	return enif_make_sub_binary(
		env,
		enif_make_binary(env, &result),
		crypto_box_BOXZEROBYTES,
		padded_msg.size - crypto_box_BOXZEROBYTES);
}

static
ERL_NIF_TERM enif_crypto_box_open(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary padded_ciphertext, nonce, pk, sk, result;
	
	if (
	  (argc != 4) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &padded_ciphertext)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &nonce)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[2], &pk)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[3], &sk))) {
		return enif_make_badarg(env);
	}
	
	if (
	  (nonce.size != crypto_box_NONCEBYTES) ||
	  (pk.size != crypto_box_PUBLICKEYBYTES) ||
	  (sk.size != crypto_box_SECRETKEYBYTES) ||
	  (padded_ciphertext.size < crypto_box_BOXZEROBYTES)) {
		return enif_make_badarg(env);
	}
	
	if (!enif_alloc_binary(padded_ciphertext.size, &result)) {
		return nacl_error_tuple(env, "alloc_failed");
	}
	
	if (crypto_box_open(result.data, padded_ciphertext.data, padded_ciphertext.size, nonce.data, pk.data, sk.data) != 0) {
		enif_release_binary(&result);
		return nacl_error_tuple(env, "failed_verification");
	}
	
	return enif_make_sub_binary(
		env,
		enif_make_binary(env, &result),
		crypto_box_ZEROBYTES,
		padded_ciphertext.size - crypto_box_ZEROBYTES);
}
/* Secret key cryptography */

static
ERL_NIF_TERM enif_crypto_secretbox_NONCEBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_secretbox_NONCEBYTES);
}

static
ERL_NIF_TERM enif_crypto_secretbox_KEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_secretbox_KEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_secretbox_ZEROBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_secretbox_ZEROBYTES);
}

static
ERL_NIF_TERM enif_crypto_secretbox_BOXZEROBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_secretbox_BOXZEROBYTES);
}

static
ERL_NIF_TERM enif_crypto_stream_KEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_stream_KEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_stream_NONCEBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_stream_NONCEBYTES);
}

static
ERL_NIF_TERM enif_crypto_auth_KEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_auth_KEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_secretbox(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary key, nonce, padded_msg, padded_ciphertext;
	
	if (
	  (argc != 3) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &padded_msg)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &nonce)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[2], &key))) {
		return enif_make_badarg(env);
	}
	
	if (
	  (key.size != crypto_secretbox_KEYBYTES) ||
	  (nonce.size != crypto_secretbox_NONCEBYTES) ||
	  (padded_msg.size < crypto_secretbox_ZEROBYTES)) {
		return enif_make_badarg(env);
	}
	
	if (!enif_alloc_binary(padded_msg.size, &padded_ciphertext)) {
		return nacl_error_tuple(env, "alloc_failed");
	}
	
	crypto_secretbox(
	  padded_ciphertext.data,
	  padded_msg.data, padded_msg.size,
	  nonce.data,
	  key.data);
	
	return enif_make_sub_binary(env,
		enif_make_binary(env, &padded_ciphertext),
		crypto_secretbox_BOXZEROBYTES,
		padded_msg.size - crypto_secretbox_BOXZEROBYTES);
}

static
ERL_NIF_TERM enif_crypto_secretbox_open(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary key, nonce, padded_ciphertext, padded_msg;
	
	if (
	  (argc != 3) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &padded_ciphertext)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &nonce)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[2], &key))) {
		return enif_make_badarg(env);
	}
	
	if (
	  (key.size != crypto_secretbox_KEYBYTES) ||
	  (nonce.size != crypto_secretbox_NONCEBYTES) ||
	  (padded_ciphertext.size < crypto_secretbox_BOXZEROBYTES)) {
		return enif_make_badarg(env);
	}
	
	if (!enif_alloc_binary(padded_ciphertext.size, &padded_msg)) {
		return nacl_error_tuple(env, "alloc_failed");
	}
	
	if (crypto_secretbox_open(
	    padded_msg.data,
	    padded_ciphertext.data,
	    padded_ciphertext.size,
	    nonce.data,
	    key.data) != 0) {
		enif_release_binary(&padded_msg);
		return nacl_error_tuple(env, "failed_verification");
	}
	
	return enif_make_sub_binary(
	    env,
	    enif_make_binary(env, &padded_msg),
	    crypto_secretbox_ZEROBYTES,
	    padded_ciphertext.size - crypto_secretbox_ZEROBYTES);
}

static
ERL_NIF_TERM enif_crypto_stream(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary c, n, k;
	ErlNifUInt64 clen;

	if (
	  (argc != 3) ||
	  (!enif_get_uint64(env, argv[0], &clen)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &n)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[2], &k))) {
		return enif_make_badarg(env);
	}
	
	if (
	  (k.size != crypto_stream_KEYBYTES) ||
	  (n.size != crypto_stream_NONCEBYTES)) {
		return enif_make_badarg(env);
	}
	
	if (!enif_alloc_binary(clen, &c)) {
		return nacl_error_tuple(env, "alloc_failed");
	}
	
	crypto_stream(c.data, c.size, n.data, k.data);
	
	return enif_make_binary(env, &c);
}

static
ERL_NIF_TERM enif_crypto_stream_xor(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary c, m, n, k;
	
	if (
	  (argc != 3) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &n)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[2], &k))) {
		return enif_make_badarg(env);
	}
	
	if (
	  (k.size != crypto_stream_KEYBYTES) ||
	  (n.size != crypto_stream_NONCEBYTES)) {
		return enif_make_badarg(env);
	}
	
	if (!enif_alloc_binary(m.size, &c)) {
		return nacl_error_tuple(env, "alloc_failed");
	}
	
	crypto_stream_xor(c.data, m.data, m.size, n.data, k.data);
	
	return enif_make_binary(env, &c);
}

static
ERL_NIF_TERM enif_crypto_auth(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary a,m,k;

	if (
	  (argc != 2) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &k))) {
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

static
ERL_NIF_TERM enif_crypto_auth_verify(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary a, m, k;
	
	if (
	  (argc != 3) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &a)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &m)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[2], &k))) {
		return enif_make_badarg(env);
	}
	
	if (
	  (k.size != crypto_auth_KEYBYTES) ||
	  (a.size != crypto_auth_BYTES)) {
		return enif_make_badarg(env);
	}
	
	if (0 == crypto_auth_verify(a.data, m.data, m.size, k.data)) {
		return enif_make_atom(env, "true");
	} else {
		return enif_make_atom(env, "false");
	}
}
	  

/* Tie the knot to the Erlang world */
static ErlNifFunc nif_funcs[] = {
	{"crypto_box_NONCEBYTES", 0, enif_crypto_box_NONCEBYTES},
	{"crypto_box_ZEROBYTES", 0, enif_crypto_box_ZEROBYTES},
	{"crypto_box_BOXZEROBYTES", 0, enif_crypto_box_BOXZEROBYTES},
	{"crypto_box_PUBLICKEYBYTES", 0, enif_crypto_box_PUBLICKEYBYTES},
	{"crypto_box_SECRETKEYBYTES", 0, enif_crypto_box_SECRETKEYBYTES},
	{"crypto_box_keypair", 0, enif_crypto_box_keypair},
	{"crypto_box", 4, enif_crypto_box, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_box_open", 4, enif_crypto_box_open, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	
	{"crypto_secretbox_NONCEBYTES", 0, enif_crypto_secretbox_NONCEBYTES},
	{"crypto_secretbox_ZEROBYTES", 0, enif_crypto_secretbox_ZEROBYTES},
	{"crypto_secretbox_BOXZEROBYTES", 0, enif_crypto_secretbox_BOXZEROBYTES},
	{"crypto_secretbox_KEYBYTES", 0, enif_crypto_secretbox_KEYBYTES},
	{"crypto_secretbox", 3, enif_crypto_secretbox, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_secretbox_open", 3, enif_crypto_secretbox_open, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_stream_KEYBYTES", 0, enif_crypto_stream_KEYBYTES},
	{"crypto_stream_NONCEBYTES", 0, enif_crypto_stream_NONCEBYTES},
	{"crypto_stream", 3, enif_crypto_stream, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_stream_xor", 3, enif_crypto_stream_xor, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_auth_KEYBYTES", 0, enif_crypto_auth_KEYBYTES},
	{"crypto_auth", 2, enif_crypto_auth, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_auth_verify", 3, enif_crypto_auth_verify, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_hash", 1, enif_crypto_hash, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};



ERL_NIF_INIT(enacl_nif, nif_funcs, NULL, NULL, NULL, NULL);
