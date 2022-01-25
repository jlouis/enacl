#include <sodium.h>
#include <string.h>

#include <erl_nif.h>

#include "enacl.h"
#include "ed25519.h"

ERL_NIF_TERM
enacl_crypto_ed25519_is_valid_point(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  ErlNifBinary p;

  if ((argc != 1) ||
      (!enif_inspect_binary(env, argv[0], &p)) ||
      (p.size != crypto_core_ed25519_BYTES)) {
    return enif_make_badarg(env);
  }

  if (1 == crypto_core_ed25519_is_valid_point(p.data)) {
    return enif_make_atom(env, "true");
  } else {
    return enif_make_atom(env, "false");
  }
}

ERL_NIF_TERM
enacl_crypto_ed25519_add(ErlNifEnv *env, int argc,
                         ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary p, q, output;

  if ((argc != 2) ||
      (!enif_inspect_binary(env, argv[0], &p)) ||
      (!enif_inspect_binary(env, argv[1], &q)) ||
      (p.size != crypto_core_ed25519_BYTES) ||
      (q.size != crypto_core_ed25519_BYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_core_ed25519_BYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    if (crypto_core_ed25519_add(output.data, p.data, q.data) != 0) {
      enif_release_binary(&output);
      result = enacl_error_tuple(env, "ed25519_add_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_sub(ErlNifEnv *env, int argc,
                         ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary p, q, output;

  if ((argc != 2) ||
      (!enif_inspect_binary(env, argv[0], &p)) ||
      (!enif_inspect_binary(env, argv[1], &q)) ||
      (p.size != crypto_core_ed25519_BYTES) ||
      (q.size != crypto_core_ed25519_BYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_core_ed25519_BYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    if (crypto_core_ed25519_sub(output.data, p.data, q.data) != 0) {
      enif_release_binary(&output);
      result = enacl_error_tuple(env, "ed25519_sub_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalarmult(ErlNifEnv *env, int argc,
                                ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary scalar, point, output;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &scalar)) ||
      (!enif_inspect_binary(env, argv[1], &point)) ||
      (scalar.size != crypto_scalarmult_ed25519_BYTES) ||
      (point.size != crypto_scalarmult_ed25519_BYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    if (crypto_scalarmult_ed25519(output.data, scalar.data, point.data) != 0) {
      enif_release_binary(&output);
      result = enacl_error_tuple(env, "scalarmult_ed25519_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalarmult_base(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary secret, output;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &secret)) ||
      (secret.size != crypto_scalarmult_ed25519_BYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_scalarmult_ed25519_BYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    if (crypto_scalarmult_ed25519_base(output.data, secret.data) != 0) {
      enif_release_binary(&output);
      result = enacl_error_tuple(env, "scalarmult_ed25519_base_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalarmult_noclamp(ErlNifEnv *env, int argc,
                                        ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary scalar, point, output;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &scalar)) ||
      (!enif_inspect_binary(env, argv[1], &point)) ||
      (scalar.size != crypto_scalarmult_ed25519_BYTES) ||
      (point.size != crypto_scalarmult_ed25519_BYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_scalarmult_curve25519_BYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    if (crypto_scalarmult_ed25519_noclamp(output.data, scalar.data, point.data) != 0) {
      enif_release_binary(&output);
      result = enacl_error_tuple(env, "scalarmult_ed25519_noclamp_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalarmult_base_noclamp(ErlNifEnv *env, int argc,
                                             ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary secret, output;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &secret)) ||
      (secret.size != crypto_scalarmult_ed25519_BYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_scalarmult_ed25519_BYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    if (crypto_scalarmult_ed25519_base_noclamp(output.data, secret.data) != 0) {
      enif_release_binary(&output);
      result = enacl_error_tuple(env, "scalarmult_ed25519_base_noclamp_failed");
      continue;
    }

    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalar_reduce(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary scalar, output;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &scalar)) ||
      (scalar.size != crypto_core_ed25519_NONREDUCEDSCALARBYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_core_ed25519_SCALARBYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    crypto_core_ed25519_scalar_reduce(output.data, scalar.data);
    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalar_negate(ErlNifEnv *env, int argc,
                                   ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary scalar, output;

  if ((argc != 1) || (!enif_inspect_binary(env, argv[0], &scalar)) ||
      (scalar.size != crypto_core_ed25519_SCALARBYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_core_ed25519_SCALARBYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    crypto_core_ed25519_scalar_negate(output.data, scalar.data);
    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalar_add(ErlNifEnv *env, int argc,
                                ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary x, y, output;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &x)) ||
      (!enif_inspect_binary(env, argv[1], &y)) ||
      (x.size != crypto_core_ed25519_SCALARBYTES) ||
      (y.size != crypto_core_ed25519_SCALARBYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_core_ed25519_SCALARBYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    crypto_core_ed25519_scalar_add(output.data, x.data, y.data);
    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalar_sub(ErlNifEnv *env, int argc,
                                ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary x, y, output;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &x)) ||
      (!enif_inspect_binary(env, argv[1], &y)) ||
      (x.size != crypto_core_ed25519_SCALARBYTES) ||
      (y.size != crypto_core_ed25519_SCALARBYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_core_ed25519_SCALARBYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    crypto_core_ed25519_scalar_sub(output.data, x.data, y.data);
    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}

ERL_NIF_TERM
enacl_crypto_ed25519_scalar_mul(ErlNifEnv *env, int argc,
                                ERL_NIF_TERM const argv[]) {
  ERL_NIF_TERM result;
  ErlNifBinary x, y, output;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &x)) ||
      (!enif_inspect_binary(env, argv[1], &y)) ||
      (x.size != crypto_core_ed25519_SCALARBYTES) ||
      (y.size != crypto_core_ed25519_SCALARBYTES)) {
    return enif_make_badarg(env);
  }

  do {
    if (!enif_alloc_binary(crypto_core_ed25519_SCALARBYTES, &output)) {
      result = enacl_internal_error(env);
      continue;
    }

    crypto_core_ed25519_scalar_mul(output.data, x.data, y.data);
    result = enif_make_binary(env, &output);
  } while (0);

  return result;
}


