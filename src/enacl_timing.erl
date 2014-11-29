%%% @doc module enacl_timing provides helpers for timing enacl toward your installation
%%% @end
-module(enacl_timing).

-export([all/0]).

all() ->
   [time_hashing(),
    time_box(),
    time_sign(),
    time_secretbox(),
    time_stream(),
    time_auth(),
    time_onetimeauth()].

-define(ROUNDS, 300).

%% ONETIMEAUTH
%% ------------

time_onetimeauth() ->
    Sz = 1024 * 128,
    M = binary:copy(<<0>>, Sz),
    K = <<"secretsecretsecretsecretsecret32">>,
    T = timed(fun() -> onetime_auth(M, K, ?ROUNDS) end) / ?ROUNDS,
    A = enacl:onetime_auth(M, K),
    T2 = timed(fun() -> onetime_auth_verify(A, M, K, ?ROUNDS) end) / ?ROUNDS,
    true = enacl:onetime_auth_verify(A, M, K),
    [
        #{ size => Sz, time => T, operation => onetime_auth },
        #{ size => Sz, time => T2, operation => onetime_auth_verify }
    ].
    
onetime_auth(_M, _K, 0) -> ok;
onetime_auth(M, K, N) ->
    enacl_nif:crypto_onetimeauth_b(M, K),
    onetime_auth(M, K, N-1).
    
onetime_auth_verify(_A, _M, _K, 0) -> ok;
onetime_auth_verify(A, M, K, N) ->
    enacl_nif:crypto_onetimeauth_verify_b(A, M, K),
    onetime_auth_verify(A, M, K, N-1).

%% AUTH
%% -----------

time_auth() ->
    Sz = 1024 * 32,
    M = binary:copy(<<0>>, Sz),
    K = <<"secretsecretsecretsecretsecret32">>,
    T = timed(fun() -> auth(M, K, ?ROUNDS) end) / ?ROUNDS,
    A = enacl:auth(M, K),
    T2 = timed(fun() -> auth_verify(A, M, K, ?ROUNDS) end) / ?ROUNDS,
    true = enacl:auth_verify(A, M, K),
    [
      #{ size => Sz, time => T, operation => auth },
      #{ size => Sz, time => T2, operation => auth_verify }
    ].

auth(_M, _K, 0) -> ok;
auth(M, K, N) ->
    enacl_nif:crypto_auth_b(M, K),
    auth(M, K, N-1).
    
auth_verify(_A, _M, _K, 0) -> ok;
auth_verify(A, M, K, N) ->
    enacl_nif:crypto_auth_verify_b(A, M, K),
    auth(M, K, N-1).

%% STREAM
%% -----------

time_stream() ->
    Sz = 1024 * 128,
    K = <<"secretsecretsecretsecretsecret32">>,
    Nonce = <<0:192>>,
    T = timed(fun () -> stream(Sz, Nonce, K, ?ROUNDS) end) / ?ROUNDS,
    M = binary:copy(<<0>>, Sz),
    T2 = timed(fun () -> stream_xor(M, Nonce, K, ?ROUNDS) end) / ?ROUNDS,
    [
      #{ size => Sz, time => T, operation => stream },
      #{ size => Sz, time => T2, operation => stream_xor }
    ].
    
stream(_Sz, _Nonce, _K, 0) -> ok;
stream(Sz, Nonce, K, N) ->
    enacl_nif:crypto_stream_b(Sz, Nonce, K),
    stream(Sz, Nonce, K, N-1).

stream_xor(_M, _Nonce, _K, 0) -> ok;
stream_xor(M, Nonce, K, N) ->
    enacl_nif:crypto_stream_xor_b(M, Nonce, K),
    stream_xor(M, Nonce, K, N-1).

%% SECRETBOX
%% ----------

time_secretbox() ->
    Sz = 1024 * 64,
    M = binary:copy(<<0>>, Sz),
    K = <<"secretsecretsecretsecretsecret32">>,
    Nonce = binary:copy(<<0:192>>),
    T = timed(fun() -> secretbox(M, Nonce, K, ?ROUNDS) end) / ?ROUNDS,
    CT = enacl:secretbox(M, Nonce, K),
    T2 = timed(fun() -> secretbox_open(CT, Nonce, K, ?ROUNDS) end) / ?ROUNDS,
    {ok, M} = enacl:secretbox_open(CT, Nonce, K),
    [
      #{ size => Sz, time => T, operation => secretbox },
      #{ size => Sz, time => T2, operation => secretbox_open }
    ].

secretbox(_M, _Nonce, _K, 0) -> ok;
secretbox(M, Nonce, K, N) ->
    enacl_nif:crypto_secretbox_b(M, Nonce, K),
    secretbox(M, Nonce, K, N-1).
    
secretbox_open(_M, _Nonce, _K, 0) -> ok;
secretbox_open(M, Nonce, K, N) ->
    enacl_nif:crypto_secretbox_open_b(M, Nonce, K),
    secretbox_open(M, Nonce, K, N-1).

%% SIGN
%% ---------
time_sign() ->
    Sz = 1024 * 16,
    M = binary:copy(<<0>>, Sz),
    #{ public := PK, secret := SK } = enacl:sign_keypair(),
    T = timed(fun() -> sign(M, SK, ?ROUNDS) end) / ?ROUNDS,
    SM = enacl:sign(M, SK),
    T2 = timed(fun() -> sign_open(SM, PK, ?ROUNDS) end) / ?ROUNDS,
    [
        #{ size => Sz, time => T, operation => sign },
        #{ size => Sz, time => T2, operation => sign_open }
    ].

sign(_M, _SK, 0) -> ok;
sign(M, SK, N) ->
    enacl_nif:crypto_sign_b(M, SK),
    sign(M, SK, N-1).
    
sign_open(_SM, _PK, 0) -> ok;
sign_open(SM, PK, N) ->
    enacl_nif:crypto_sign_open_b(SM, PK),
    sign_open(SM, PK, N-1).

%% BOX
%% --------
time_box() ->
    Sz = 1024 * 32,
    ZB = binary:copy(<<0>>, enacl_nif:crypto_box_ZEROBYTES()),
    BZB = binary:copy(<<0>>, enacl_nif:crypto_box_BOXZEROBYTES()),
    Bin = binary:copy(<<0>>, Sz),
    Nonce = binary:copy(<<0>>, enacl_nif:crypto_box_NONCEBYTES()),
    #{ public := PK1, secret := SK1 } = enacl:box_keypair(),
    #{ public := PK2, secret := SK2 } = enacl:box_keypair(),
    T = timed(fun() -> box([ZB, Bin], Nonce, PK1, SK2, ?ROUNDS) end) / ?ROUNDS,
    Boxed = enacl:box([ZB, Bin], Nonce, PK1, SK2),
    T2 = timed(fun() -> box_open([BZB, Boxed], Nonce, PK2, SK1, ?ROUNDS) end) / ?ROUNDS,
    [
      #{ size => Sz, time => T, operation => box},
      #{ size => Sz, time => T2, operation => box_open}
    ].

box_open(_Bin, _Nonce, _PK, _SK, 0) -> ok;
box_open(Bin, Nonce, PK, SK, N) ->
    enacl_nif:crypto_box_open_b(Bin, Nonce, PK, SK),
    box_open(Bin, Nonce, PK, SK, N-1).

box(_Bin, _Nonce, _PK, _SK, 0) -> ok;
box(Bin, Nonce, PK, SK, N) ->
    enacl_nif:crypto_box_b(Bin, Nonce, PK, SK),
    box(Bin, Nonce, PK, SK, N-1).

%% HASHING
%% ----------------
time_hashing() ->
    Sz = 1024 * 32,
    Bin = binary:copy(<<0>>, Sz),
    T = timed(fun() -> hash(Bin, ?ROUNDS) end) / ?ROUNDS,
    #{ size => Sz, time => T, operation => hash}.
    
hash(_Bin, 0) -> ok;
hash(Bin, N) ->
    enacl_nif:crypto_hash_b(Bin),
    hash(Bin, N-1).
    
%% Helpers
timed(Fun) ->
    Fun(), % warmup
    {T, _} = timer:tc(Fun),
    T.
 
