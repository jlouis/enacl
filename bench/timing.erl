-module(timing).
-export([test/0]).

test() ->
    randombytes(),
    randombytes(),
    randombytes(),
    hash(),
    box_keypair(),
    box(),
    box_before_after(),
    sign_keypair(),
    sign(),
    secretbox(),
    stream(),
    auth(),
    onetime_auth(),
    scalarmult(),
    ok.

randombytes() ->
    randombytes(100*1000).

randombytes(0) -> ok;
randombytes(N) ->
    enacl:randombytes(1024),
    randombytes(N-1).

hash() ->
    B = binary:copy(<<0>>, 4096),
    hash(B, 10*1000).

hash(_B, 0) -> ok;
hash(B, N) ->
    enacl:hash(B),
    hash(B, N-1).

box_keypair() ->
    box_keypair(10*1000).

box_keypair(0) -> ok;
box_keypair(N) ->
    enacl:box_keypair(),
    box_keypair(N-1).

box() ->
    #{ public := PK1} = enacl:box_keypair(),
    #{ secret := SK2} = enacl:box_keypair(),
    B = binary:copy(<<0>>, 1),
    Nonce = binary:copy(<<0>>, enacl:box_NONCEBYTES()()),
    box(B, Nonce, PK1, SK2, 10*1000).

box(_B, _Nonce, _PK1, _SK2, 0) -> ok;
box(B, Nonce, PK1, SK2, N) ->
    enacl:box(B, Nonce, PK1, SK2),
    enacl:box_seal(B, PK1),
    box(B, Nonce, PK1, SK2, N-1).

box_before_after() ->
    #{ public := PK1 } = enacl:box_keypair(),
    #{ secret := SK2 } = enacl:box_keypair(),
    box_beforenm(PK1, SK2, 10*1000),
    R = enacl:box_beforenm(PK1, SK2),
    B = binary:copy(<<0>>, 8192),
    Nonce = binary:copy(<<0>>, enacl:box_NONCEBYTES()()),
    box_afternm(B, Nonce, R, 10*1000),
    ok.

box_beforenm(_PK, _SK, 0) -> ok;
box_beforenm(PK, SK, N) ->
    enacl:box_beforenm(PK, SK),
    box_beforenm(PK, SK, N-1).

box_afternm(_Msg, _Nonce, _Key, 0) -> ok;
box_afternm(Msg, Nonce, Key, N) ->
    enacl:box_afternm(Msg, Nonce, Key),
    box_afternm(Msg, Nonce, Key, N-1).

sign_keypair() ->
    sign_keypair(10*1000).

sign_keypair(0) -> ok;
sign_keypair(N) ->
    enacl:sign_keypair(),
    #{ public := PK, secret := SK} = enacl:crypto_sign_ed25519_keypair(),
    enacl:crypto_sign_ed25519_public_to_curve25519(PK),
    enacl:crypto_sign_ed25519_secret_to_curve25519(SK),
    sign_keypair(N-1).

sign() ->
    Msg = binary:copy(<<0>>, 1024),
    #{ secret := SK } = enacl:sign_keypair(),
    sign(Msg, SK, 10*1000).

sign(_Msg, _SK, 0) -> ok;
sign(Msg, SK, N) ->
    enacl:sign(Msg, SK),
    enacl:sign_detached(Msg, SK),
    sign(Msg, SK, N-1).

secretbox() ->
    Msg = binary:copy(<<0>>, 8192),
    Nonce = binary:copy(<<0>>, enacl:secretbox_NONCEBYTES()()),
    Key = binary:copy(<<0>>, enacl:secretbox_KEYBYTES()),
    secretbox(Msg, Nonce, Key, 10*1000).

secretbox(_Msg, _Nonce, _Key, 0) -> ok;
secretbox(Msg, Nonce, Key, N) ->
    enacl:secretbox(Msg, Nonce, Key),
    secretbox(Msg, Nonce, Key, N-1).


stream() ->
    stream(16384, binary:copy(<<0>>, enacl:stream_NONCEBYTES()), binary:copy(<<0>>, enacl:stream_KEYBYTES()), 10*1000).

stream(_L, _Nonce, _K, 0) -> ok;
stream(L, Nonce, K, N) ->
    enacl:stream(L, Nonce, K),
    stream(L, Nonce, K, N-1).

auth() ->
    Msg = binary:copy(<<0>>, 4096),
    Key = binary:copy(<<0>>, enacl:auth_KEYBYTES()),
    auth(Msg, Key, 10*1000).

auth(_Msg, _Key, 0) -> ok;
auth(Msg, Key, N) ->
    enacl:auth(Msg, Key),
    auth(Msg, Key, N-1).

onetime_auth() ->
    Msg = binary:copy(<<0>>, 16384),
    Key = binary:copy(<<0>>, enacl:onetime_auth_KEYBYTES()),
    onetime_auth(Msg, Key, 10*1000).

onetime_auth(_Msg, _Key, 0) -> ok;
onetime_auth(Msg, Key, N) ->
    enacl:onetime_auth(Msg, Key),
    onetime_auth(Msg, Key, N-1).

scalarmult() ->
    Secret = binary:copy(<<0>>, 32),
    BasePoint = binary:copy(<<1>>, 32),
    scalarmult(Secret, BasePoint, 10*1000).

scalarmult(_S, _B, 0) -> ok;
scalarmult(S, B, N) ->
    enacl:curve25519_scalarmult(S, B),
    scalarmult(S, B, N-1).

