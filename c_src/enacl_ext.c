#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "enacl_ext.h"

static void uint64_pack(unsigned char *y, ErlNifUInt64 x) {
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
  x >>= 8;
  *y++ = x;
}

static ErlNifUInt64 uint64_unpack(const unsigned char *x) {
  ErlNifUInt64 result;

  result = x[7];
  result <<= 8;
  result |= x[6];
  result <<= 8;
  result |= x[5];
  result <<= 8;
  result |= x[4];
  result <<= 8;
  result |= x[3];
  result <<= 8;
  result |= x[2];
  result <<= 8;
  result |= x[1];
  result <<= 8;
  result |= x[0];
  return result;
}

static int crypto_block(unsigned char *out, const unsigned char *in,
                        const unsigned char *k) {
  ErlNifUInt64 v0 = uint64_unpack(in + 0);
  ErlNifUInt64 v1 = uint64_unpack(in + 8);
  ErlNifUInt64 k0 = uint64_unpack(k + 0);
  ErlNifUInt64 k1 = uint64_unpack(k + 8);
  ErlNifUInt64 k2 = uint64_unpack(k + 16);
  ErlNifUInt64 k3 = uint64_unpack(k + 24);
  ErlNifUInt64 sum = 0;
  ErlNifUInt64 delta = 0x9e3779b97f4a7c15;
  int i;
  for (i = 0; i < 32; ++i) {
    sum += delta;
    v0 += ((v1 << 7) + k0) ^ (v1 + sum) ^ ((v1 >> 12) + k1);
    v1 += ((v0 << 16) + k2) ^ (v0 + sum) ^ ((v0 >> 8) + k3);
  }
  uint64_pack(out + 0, v0);
  uint64_pack(out + 8, v1);

  return 0;
}

ERL_NIF_TERM enif_scramble_block_16(ErlNifEnv *env, int argc,
                                    ERL_NIF_TERM const argv[]) {
  ErlNifBinary in, out, key;

  if ((argc != 2) || (!enif_inspect_binary(env, argv[0], &in)) ||
      (!enif_inspect_binary(env, argv[1], &key)) || (in.size != 16) ||
      (key.size != 32)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(in.size, &out)) {
    return enacl_internal_error(env);
  }

  crypto_block(out.data, in.data, key.data);

  return enif_make_binary(env, &out);
}