-module(enacl_eqc).
-include_lib("eqc/include/eqc.hrl").
-compile(export_all).

%% CRYPTO BOX
%% ---------------------------

prop_box_keypair() ->
    ?FORALL(_X, return(dummy),
        ok_box(enacl:box_keypair())).
       
ok_box({ok, _PK, _SK}) -> true;
ok_box(_) -> false.


%% HASHING
%% ---------------------------
diff_pair(Sz) ->
    ?SUCHTHAT({X, Y}, {binary(Sz), binary(Sz)},
        X /= Y).

prop_crypto_hash_eq() ->
    ?FORALL(Sz, oneof([1, 128, 1024, 1024*4]),
    ?FORALL(X, binary(Sz),
        equals(enacl:hash(X), enacl:hash(X))
    )).
    
prop_crypto_hash_neq() ->
    ?FORALL(Sz, oneof([1, 128, 1024, 1024*4]),
    ?FORALL({X, Y}, diff_pair(Sz),
        enacl:hash(X) /= enacl:hash(Y)
    )).

