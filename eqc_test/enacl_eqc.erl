-module(enacl_eqc).
-include_lib("eqc/include/eqc.hrl").
-compile(export_all).

nonce() ->
    Sz = enacl:box_nonce_size(),
    binary(Sz).

%% CRYPTO BOX
%% ---------------------------


prop_box_keypair() ->
    ?FORALL(_X, return(dummy),
        ok_box(enacl:box_keypair())).
       
ok_box({ok, _PK, _SK}) -> true;
ok_box(_) -> false.

prop_box_correct() ->
    ?FORALL({Msg, Nonce}, {binary(), nonce()},
        begin
            {ok, PK1, SK1} = enacl:box_keypair(),
            {ok, PK2, SK2} = enacl:box_keypair(),
            CipherText = enacl:box(Msg, Nonce, PK2, SK1),
            {ok, DecodedMsg} = enacl:box_open(CipherText, Nonce, PK1, SK2),
            equals(Msg, DecodedMsg)
        end).

prop_box_failure_integrity() ->
    ?FORALL({Msg, Nonce}, {binary(), nonce()},
        begin
            {ok, PK1, SK1} = enacl:box_keypair(),
            {ok, PK2, SK2} = enacl:box_keypair(),
            CipherText = enacl:box(Msg, Nonce, PK2, SK1),
            Err = enacl:box_open([<<"x">>, CipherText], Nonce, PK1, SK2),
            equals(Err, {error, failed_verification})
        end).

%% CRYPTO SECRET BOX
%% -------------------------------

secret_key() ->
    Sz = enacl:secretbox_key_size(),
    binary(Sz).

prop_secretbox_correct() ->
    ?FORALL({Msg, Nonce, Key}, {binary(), nonce(), secret_key()},
      begin
        CipherText = enacl:secretbox(Msg, Nonce, Key),
        {ok, DecodedMsg} = enacl:secretbox_open(CipherText, Nonce, Key),
        equals(Msg, DecodedMsg)
      end).
      
prop_secretbox_failure_integrity() ->
    ?FORALL({Msg, Nonce, Key}, {binary(), nonce(), secret_key()},
      begin
        CipherText = enacl:secretbox(Msg, Nonce, Key),
        Err = enacl:secretbox_open([<<"x">>, CipherText], Nonce, Key),
        equals(Err, {error, failed_verification})
      end).

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

