#include <erl_nif.h>

#include "enacl.h"

ERL_NIF_TERM enacl_error_tuple(ErlNifEnv *env, char *error_atom) {
  return enif_make_tuple2(env, enif_make_atom(env, "error"),
                          enif_make_atom(env, error_atom));
}
