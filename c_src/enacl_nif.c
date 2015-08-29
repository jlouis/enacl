#include "erl_nif.h"

#include <string.h>

#include <sodium.h>

#ifndef ERL_NIF_DIRTY_SCHEDULER_SUPPORT
# error Requires dirty schedulers
#endif

/* Errors */
static
ERL_NIF_TERM nacl_error_tuple(ErlNifEnv *env, char *error_atom) {
	return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error_atom));
}

/* Initialization */
static
int enif_crypto_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
	sodium_init();
	return 0;
}

/* Low-level functions (Hashing, String Equality, ...) */

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

static
ERL_NIF_TERM enif_crypto_verify_16(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary x,y;

	if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &x))
	  || (!enif_inspect_binary(env, argv[1], &y))) {
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

static
ERL_NIF_TERM enif_crypto_verify_32(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary x,y;

	if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &x))
	  || (!enif_inspect_binary(env, argv[1], &y))) {
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

/* Curve 25519 */
static
ERL_NIF_TERM enif_crypto_curve25519_scalarmult(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ERL_NIF_TERM result;
	ErlNifBinary secret, basepoint, output;
	uint8_t bp[crypto_scalarmult_curve25519_BYTES];

	if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &secret))
			|| (!enif_inspect_binary(env, argv[1], &basepoint))
			|| (secret.size != crypto_scalarmult_curve25519_BYTES)
			|| (basepoint.size != crypto_scalarmult_curve25519_BYTES)) {
		return enif_make_badarg(env);
	}

	memcpy(bp, basepoint.data, crypto_scalarmult_curve25519_BYTES);

	/* Clear the high-bit. Better safe than sorry. */
	bp[31] &= 0x7f;

	do
	{
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

/* Ed 25519 */
static
ERL_NIF_TERM enif_crypto_sign_ed25519_keypair(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
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

	return enif_make_tuple2(env, enif_make_binary(env, &pk), enif_make_binary(env, &sk));
}

static
ERL_NIF_TERM enif_crypto_sign_ed25519_public_to_curve25519(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary curve25519_pk, ed25519_pk;

	if ((argc != 1)
			|| (!enif_inspect_binary(env, argv[0], &ed25519_pk))
			|| (ed25519_pk.size != crypto_sign_ed25519_PUBLICKEYBYTES)) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &curve25519_pk)) {
		return nacl_error_tuple(env, "alloc_failed");
	}

	if (crypto_sign_ed25519_pk_to_curve25519(curve25519_pk.data, ed25519_pk.data) != 0) {
		return nacl_error_tuple(env, "ed25519_public_to_curve25519_failed");
	}

	return enif_make_binary(env, &curve25519_pk);
}

static
ERL_NIF_TERM enif_crypto_sign_ed25519_secret_to_curve25519(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary curve25519_sk, ed25519_sk;

	if ((argc != 1)
			|| (!enif_inspect_binary(env, argv[0], &ed25519_sk))
			|| (ed25519_sk.size != crypto_sign_ed25519_SECRETKEYBYTES)) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &curve25519_sk)) {
		return nacl_error_tuple(env, "alloc_failed");
	}

	if (crypto_sign_ed25519_sk_to_curve25519(curve25519_sk.data, ed25519_sk.data) != 0) {
		return nacl_error_tuple(env, "ed25519_secret_to_curve25519_failed");
	}

	return enif_make_binary(env, &curve25519_sk);
}

static
ERL_NIF_TERM enif_crypto_sign_ed25519_PUBLICKEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_sign_ed25519_PUBLICKEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_sign_ed25519_SECRETKEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_sign_ed25519_SECRETKEYBYTES);
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
ERL_NIF_TERM enif_crypto_box_BEFORENMBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_box_BEFORENMBYTES);
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

	return enif_make_tuple2(env, enif_make_binary(env, &pk), enif_make_binary(env, &sk));
}

static
ERL_NIF_TERM enif_crypto_box(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary padded_msg, nonce, pk, sk, result;

	if (
	  (argc != 4) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &padded_msg)) ||
	  (!enif_inspect_binary(env, argv[1], &nonce)) ||
	  (!enif_inspect_binary(env, argv[2], &pk)) ||
	  (!enif_inspect_binary(env, argv[3], &sk))) {
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
	  (!enif_inspect_binary(env, argv[1], &nonce)) ||
	  (!enif_inspect_binary(env, argv[2], &pk)) ||
	  (!enif_inspect_binary(env, argv[3], &sk))) {
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

	if (0 != crypto_box_open(result.data, padded_ciphertext.data, padded_ciphertext.size, nonce.data, pk.data, sk.data)) {
		enif_release_binary(&result);
		return nacl_error_tuple(env, "failed_verification");
	}

	return enif_make_sub_binary(
		env,
		enif_make_binary(env, &result),
		crypto_box_ZEROBYTES,
		padded_ciphertext.size - crypto_box_ZEROBYTES);
}

/* Precomputed crypto boxes */

static
ERL_NIF_TERM enif_crypto_box_beforenm(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary k, pk, sk;

	if (
	    (argc != 2) ||
	    (!enif_inspect_binary(env, argv[0], &pk)) ||
	    (!enif_inspect_binary(env, argv[1], &sk)) ||
	    (pk.size != crypto_box_PUBLICKEYBYTES) ||
	    (sk.size != crypto_box_SECRETKEYBYTES)) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary(crypto_box_BEFORENMBYTES, &k)) {
		return nacl_error_tuple(env, "alloc_failed");
	}

	crypto_box_beforenm(k.data, pk.data, sk.data);

	return enif_make_binary(env, &k);
}

static
ERL_NIF_TERM enif_crypto_box_afternm(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary result, m, nonce, k;

	if (
	    (argc != 3) ||
	    (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
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

	return enif_make_sub_binary(
		env,
		enif_make_binary(env, &result),
		crypto_box_BOXZEROBYTES,
		m.size - crypto_box_BOXZEROBYTES);
}

static
ERL_NIF_TERM enif_crypto_box_open_afternm(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary result, m, nonce, k;

	if (
	    (argc != 3) ||
	    (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
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

	if (0 != crypto_box_open_afternm(result.data, m.data, m.size, nonce.data, k.data)) {
		enif_release_binary(&result);
		return nacl_error_tuple(env, "failed_verification");
	}

	return enif_make_sub_binary(
		env,
		enif_make_binary(env, &result),
		crypto_box_ZEROBYTES,
		m.size - crypto_box_ZEROBYTES);
}

/* Signing */
static
ERL_NIF_TERM enif_crypto_sign_PUBLICKEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_sign_PUBLICKEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_sign_SECRETKEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_sign_SECRETKEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_sign_keypair(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
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

	return enif_make_tuple2(env, enif_make_binary(env, &pk), enif_make_binary(env, &sk));
}

/*
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *sk);
 */
static
ERL_NIF_TERM enif_crypto_sign(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary m, sk, sm;
	unsigned long long smlen;

	if (
	  (argc != 2) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
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
static
ERL_NIF_TERM enif_crypto_sign_open(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary m, sm, pk;
	unsigned long long mlen;

	if (
	  (argc != 2) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &sm)) ||
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
static
ERL_NIF_TERM enif_crypto_sign_detached(ErlNifEnv* env, int argc, ERL_NIF_TERM const argv[]) {
        ErlNifBinary m, sk, sig;
        unsigned long long siglen;

        if (
            (argc != 2) ||
            (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
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
static
ERL_NIF_TERM enif_crypto_sign_verify_detached(ErlNifEnv* env, int argc, ERL_NIF_TERM const argv[]) {
        ErlNifBinary m, sig, pk;

        if (
            (argc != 3) ||
            (!enif_inspect_binary(env, argv[0], &sig)) ||
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

/* Sealed box functions */

static
ERL_NIF_TERM enif_crypto_box_SEALBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_box_SEALBYTES);
}

static
ERL_NIF_TERM enif_crypto_box_seal(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary key, msg, ciphertext;

	if (
	  (argc != 2) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &msg)) ||
	  (!enif_inspect_binary(env, argv[1], &key))) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary(msg.size + crypto_box_SEALBYTES, &ciphertext)) {
		return nacl_error_tuple(env, "alloc_failed");
	}

	crypto_box_seal(
	  ciphertext.data,
	  msg.data,
	  msg.size,
	  key.data);

	return enif_make_binary(env, &ciphertext);
}


static
ERL_NIF_TERM enif_crypto_box_seal_open(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary pk, sk, ciphertext, msg;

	if (
	  (argc != 3) ||
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

	if (crypto_box_seal_open(
	    msg.data,
	    ciphertext.data,
	    ciphertext.size,
	    pk.data,
	    sk.data) != 0) {
		enif_release_binary(&msg);
		return nacl_error_tuple(env, "failed_verification");
	}

	return enif_make_binary(env, &msg);
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
ERL_NIF_TERM enif_crypto_auth_BYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_auth_BYTES);
}

static
ERL_NIF_TERM enif_crypto_auth_KEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_auth_KEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_onetimeauth_BYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_onetimeauth_BYTES);
}

static
ERL_NIF_TERM enif_crypto_onetimeauth_KEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	return enif_make_int64(env, crypto_onetimeauth_KEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_secretbox(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary key, nonce, padded_msg, padded_ciphertext;

	if (
	  (argc != 3) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &padded_msg)) ||
	  (!enif_inspect_binary(env, argv[1], &nonce)) ||
	  (!enif_inspect_binary(env, argv[2], &key))) {
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
	  (!enif_inspect_binary(env, argv[1], &nonce)) ||
	  (!enif_inspect_binary(env, argv[2], &key))) {
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
	  (!enif_inspect_binary(env, argv[1], &n)) ||
	  (!enif_inspect_binary(env, argv[2], &k))) {
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
	  (!enif_inspect_binary(env, argv[1], &n)) ||
	  (!enif_inspect_binary(env, argv[2], &k))) {
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

static
ERL_NIF_TERM enif_crypto_auth_verify(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary a, m, k;

	if (
	  (argc != 3) ||
	  (!enif_inspect_binary(env, argv[0], &a)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &m)) ||
	  (!enif_inspect_binary(env, argv[2], &k))) {
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

static
ERL_NIF_TERM enif_crypto_onetimeauth(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary a,m,k;

	if (
	  (argc != 2) ||
	  (!enif_inspect_iolist_as_binary(env, argv[0], &m)) ||
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

static
ERL_NIF_TERM enif_crypto_onetimeauth_verify(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
	ErlNifBinary a, m, k;

	if (
	  (argc != 3) ||
	  (!enif_inspect_binary(env, argv[0], &a)) ||
	  (!enif_inspect_iolist_as_binary(env, argv[1], &m)) ||
	  (!enif_inspect_binary(env, argv[2], &k))) {
		return enif_make_badarg(env);
	}

	if (
	  (k.size != crypto_onetimeauth_KEYBYTES) ||
	  (a.size != crypto_onetimeauth_BYTES)) {
		return enif_make_badarg(env);
	}

	if (0 == crypto_onetimeauth_verify(a.data, m.data, m.size, k.data)) {
		return enif_make_atom(env, "true");
	} else {
		return enif_make_atom(env, "false");
	}
}

static
ERL_NIF_TERM enif_randombytes(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
	size_t req_size;
	ErlNifBinary result;

	if ((argc != 1) || (!enif_get_uint64(env, argv[0], &req_size))) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary(req_size, &result)) {
		return nacl_error_tuple(env, "alloc_failed");
	}

	randombytes(result.data, result.size);

	return enif_make_binary(env, &result);
}

/* Various other helper functions */
static
void uint64_pack(unsigned char *y, ErlNifUInt64 x)
{
	*y++ = x; x >>= 8;
	*y++ = x; x >>= 8;
	*y++ = x; x >>= 8;
	*y++ = x; x >>= 8;
	*y++ = x; x >>= 8;
	*y++ = x; x >>= 8;
	*y++ = x; x >>= 8;
	*y++ = x; x >>= 8;
}

static
ErlNifUInt64 uint64_unpack(const unsigned char *x)
{
	ErlNifUInt64 result;

	result = x[7];
	result <<= 8; result |= x[6];
	result <<= 8; result |= x[5];
	result <<= 8; result |= x[4];
	result <<= 8; result |= x[3];
	result <<= 8; result |= x[2];
	result <<= 8; result |= x[1];
	result <<= 8; result |= x[0];
	return result;
}

static
int crypto_block(unsigned char *out, const unsigned char *in, const unsigned char *k)
{
	ErlNifUInt64 v0 = uint64_unpack(in + 0);
	ErlNifUInt64 v1 = uint64_unpack(in + 8);
	ErlNifUInt64 k0 = uint64_unpack(k + 0);
	ErlNifUInt64 k1 = uint64_unpack(k + 8);
	ErlNifUInt64 k2 = uint64_unpack(k + 16);
	ErlNifUInt64 k3 = uint64_unpack(k + 24);
	ErlNifUInt64 sum = 0;
	ErlNifUInt64 delta = 0x9e3779b97f4a7c15;
	int i;
	for (i = 0;i < 32;++i) {
		sum += delta;
		v0 += ((v1<<7) + k0) ^ (v1 + sum) ^ ((v1>>12) + k1);
		v1 += ((v0<<16) + k2) ^ (v0 + sum) ^ ((v0>>8) + k3);
	}
	uint64_pack(out + 0,v0);
	uint64_pack(out + 8,v1);

	return 0;
}

static
ERL_NIF_TERM enif_scramble_block_16(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
	ErlNifBinary in, out, key;

	if (
	  (argc != 2) ||
	  (!enif_inspect_binary(env, argv[0], &in)) ||
	  (!enif_inspect_binary(env, argv[1], &key)) ||
	  (in.size != 16) || (key.size != 32)) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary(in.size, &out)) {
		return nacl_error_tuple(env, "alloc_failed");
	}

	crypto_block(out.data, in.data, key.data);

	return enif_make_binary(env, &out);
}

/* Tie the knot to the Erlang world */
static ErlNifFunc nif_funcs[] = {
	{"crypto_box_NONCEBYTES", 0, enif_crypto_box_NONCEBYTES},
	{"crypto_box_ZEROBYTES", 0, enif_crypto_box_ZEROBYTES},
	{"crypto_box_BOXZEROBYTES", 0, enif_crypto_box_BOXZEROBYTES},
	{"crypto_box_PUBLICKEYBYTES", 0, enif_crypto_box_PUBLICKEYBYTES},
	{"crypto_box_SECRETKEYBYTES", 0, enif_crypto_box_SECRETKEYBYTES},
	{"crypto_box_BEFORENMBYTES", 0, enif_crypto_box_BEFORENMBYTES},

	{"crypto_box_keypair", 0, enif_crypto_box_keypair, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_box", 4, enif_crypto_box, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_box_open", 4, enif_crypto_box_open, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_box_beforenm", 2, enif_crypto_box_beforenm},
	{"crypto_box_afternm_b", 3, enif_crypto_box_afternm},
	{"crypto_box_afternm", 3, enif_crypto_box_afternm, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_box_open_afternm_b", 3, enif_crypto_box_open_afternm},
	{"crypto_box_open_afternm", 3, enif_crypto_box_open_afternm, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_sign_PUBLICKEYBYTES", 0, enif_crypto_sign_PUBLICKEYBYTES},
	{"crypto_sign_SECRETKEYBYTES", 0, enif_crypto_sign_SECRETKEYBYTES},
	{"crypto_sign_keypair", 0, enif_crypto_sign_keypair, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_sign", 2, enif_crypto_sign, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_sign_open", 2, enif_crypto_sign_open, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_sign_detached", 2, enif_crypto_sign_detached, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_sign_verify_detached", 3, enif_crypto_sign_verify_detached, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_box_SEALBYTES", 0, enif_crypto_box_SEALBYTES},

	{"crypto_box_seal", 2, enif_crypto_box_seal, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_box_seal_open", 3, enif_crypto_box_seal_open, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_secretbox_NONCEBYTES", 0, enif_crypto_secretbox_NONCEBYTES},
	{"crypto_secretbox_ZEROBYTES", 0, enif_crypto_secretbox_ZEROBYTES},
	{"crypto_secretbox_BOXZEROBYTES", 0, enif_crypto_secretbox_BOXZEROBYTES},
	{"crypto_secretbox_KEYBYTES", 0, enif_crypto_secretbox_KEYBYTES},
	{"crypto_secretbox_b", 3, enif_crypto_secretbox},
	{"crypto_secretbox", 3, enif_crypto_secretbox, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_secretbox_open_b", 3, enif_crypto_secretbox_open},
	{"crypto_secretbox_open", 3, enif_crypto_secretbox_open, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_stream_KEYBYTES", 0, enif_crypto_stream_KEYBYTES},
	{"crypto_stream_NONCEBYTES", 0, enif_crypto_stream_NONCEBYTES},
	{"crypto_stream_b", 3, enif_crypto_stream},
	{"crypto_stream", 3, enif_crypto_stream, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_stream_xor_b", 3, enif_crypto_stream_xor},
	{"crypto_stream_xor", 3, enif_crypto_stream_xor, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_auth_BYTES", 0, enif_crypto_auth_BYTES},
	{"crypto_auth_KEYBYTES", 0, enif_crypto_auth_KEYBYTES},
	{"crypto_auth_b", 2, enif_crypto_auth},
	{"crypto_auth", 2, enif_crypto_auth, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_auth_verify_b", 3, enif_crypto_auth_verify},
	{"crypto_auth_verify", 3, enif_crypto_auth_verify, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_onetimeauth_BYTES", 0, enif_crypto_onetimeauth_BYTES},
	{"crypto_onetimeauth_KEYBYTES", 0, enif_crypto_onetimeauth_KEYBYTES},
	{"crypto_onetimeauth_b", 2, enif_crypto_onetimeauth},
	{"crypto_onetimeauth", 2, enif_crypto_onetimeauth, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_onetimeauth_verify_b", 3, enif_crypto_onetimeauth_verify},
	{"crypto_onetimeauth_verify", 3, enif_crypto_onetimeauth_verify, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"crypto_hash_b", 1, enif_crypto_hash},
	{"crypto_hash", 1, enif_crypto_hash, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_verify_16", 2, enif_crypto_verify_16},
	{"crypto_verify_32", 2, enif_crypto_verify_32},

	{"crypto_curve25519_scalarmult", 2, enif_crypto_curve25519_scalarmult},

	{"crypto_sign_ed25519_keypair", 0, enif_crypto_sign_ed25519_keypair, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{"crypto_sign_ed25519_public_to_curve25519", 1, enif_crypto_sign_ed25519_public_to_curve25519},
	{"crypto_sign_ed25519_secret_to_curve25519", 1, enif_crypto_sign_ed25519_secret_to_curve25519},
	{"crypto_sign_ed25519_PUBLICKEYBYTES", 0, enif_crypto_sign_ed25519_PUBLICKEYBYTES},
	{"crypto_sign_ed25519_SECRETKEYBYTES", 0, enif_crypto_sign_ed25519_SECRETKEYBYTES},

	{"randombytes_b", 1, enif_randombytes},
	{"randombytes", 1, enif_randombytes, ERL_NIF_DIRTY_JOB_CPU_BOUND},

	{"scramble_block_16", 2, enif_scramble_block_16}
};

ERL_NIF_INIT(enacl_nif, nif_funcs, enif_crypto_load, NULL, NULL, NULL);
