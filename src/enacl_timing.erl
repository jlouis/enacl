%%% @doc module enacl_timing provides helpers for timing enacl toward your installation
%%% @end
-module(enacl_timing).

-export([all/0]).

all() ->
   [time_hashing(),
    time_box()].

-define(ROUNDS, 300).

time_box() ->
    Sz = 1024 * 32,
    ZB = binary:copy(<<0>>, enacl_nif:crypto_box_ZEROBYTES()),
    BZB = binary:copy(<<0>>, enacl_nif:crypto_box_BOXZEROBYTES()),
    Bin = binary:copy(<<0>>, Sz),
    Nonce = binary:copy(<<0>>, enacl_nif:crypto_box_NONCEBYTES()),
    #{ public := PK1, secret := SK1 } = enacl:box_keypair(),
    #{ public := PK2, secret := SK2 } = enacl:box_keypair(),
    box([ZB, Bin], Nonce, PK1, SK2, ?ROUNDS),
    T = timed(fun() -> box([ZB, Bin], Nonce, PK1, SK2, ?ROUNDS) end) / ?ROUNDS,
    Boxed = enacl:box([ZB, Bin], Nonce, PK1, SK2),
    box_open([BZB, Boxed], Nonce, PK2, SK1, ?ROUNDS),
    T2 = timed(fun() -> box_open([BZB, Boxed], Nonce, PK2, SK1, ?ROUNDS) end) / ?ROUNDS,
    [
      #{ size => Sz, time => T, operation => box},
      #{ size => Sz, time => T2, operation => box_open}
    ].

%% BOX
%% --------
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
    hash(Bin, ?ROUNDS),
    T = timed(fun() -> hash(Bin, ?ROUNDS) end) / ?ROUNDS,
    #{ size => Sz, time => T, operation => hash}.
    
hash(_Bin, 0) -> ok;
hash(Bin, N) ->
    enacl_nif:crypto_hash_b(Bin),
    hash(Bin, N-1).
    
%% Helpers
timed(Fun) ->
    {T, _} = timer:tc(Fun),
    T.
 
