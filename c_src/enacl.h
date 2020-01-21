#ifndef ENACL_H
#define ENACL_H

#include <erl_nif.h>

#define ATOM_OK "ok"
#define ATOM_ERROR "error"
#define ATOM_TRUE "true"
#define ATOM_FALSE "false"

ERL_NIF_TERM enacl_error_tuplee(ErlNifEnv *, char *);

#endif
