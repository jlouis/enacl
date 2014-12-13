-module(enacl_eqc).
-include_lib("eqc/include/eqc.hrl").
-compile(export_all).

%% Generator for binaries of a given size with different properties and fault injection:
g_binary(Sz) ->
    fault(g_binary_bad(Sz), g_binary_good(Sz)).

g_binary_good(Sz) when Sz =< 32 -> binary(Sz);
g_binary_good(Sz) -> eqc_gen:largebinary(Sz).

g_binary_bad(Sz) ->
    frequency([
        {5, ?SUCHTHAT(B, binary(), byte_size(B) /= Sz)},
        {1, elements([a, b])},
        {1, int()}
    ]).
    
v_binary(Sz, N) when is_binary(N) ->
    byte_size(N) == Sz;
v_binary(_, _) -> false.

nonce() -> g_binary(enacl:box_nonce_size()).
nonce_valid(N) -> v_binary(enacl:box_nonce_size(), N).

keypair_good() ->
    #{ public := PK, secret := SK} = enacl:box_keypair(),
    {PK, SK}.

keypair_bad() ->
    ?LET(X, elements([pk, sk]),
      begin
        #{ public := PK, secret := SK} = enacl:box_keypair(),
        case X of
            pk ->
              PKBytes = enacl:box_public_key_bytes(),
              {oneof([return(a), nat(), ?SUCHTHAT(B, binary(), byte_size(B) /= PKBytes)]), SK};
            sk ->
              SKBytes = enacl:box_secret_key_bytes(),
              {PK, oneof([return(a), nat(), ?SUCHTHAT(B, binary(), byte_size(B) /= SKBytes)])}
        end
      end).

keypair() ->
    fault(keypair_bad(), keypair_good()).

%% CRYPTO BOX
%% ---------------------------

keypair_valid(PK, SK) when is_binary(PK), is_binary(SK) ->
    PKBytes = enacl:box_public_key_bytes(),
    SKBytes = enacl:box_secret_key_bytes(),
    byte_size(PK) == PKBytes andalso byte_size(SK) == SKBytes;
keypair_valid(_PK, _SK) -> false.

prop_box_keypair() ->
    ?FORALL(_X, return(dummy),
        ok_box_keypair(enacl:box_keypair())).

ok_box_keypair(#{ public := _, secret := _}) -> true;
ok_box_keypair(_) -> false.

box(Msg, Nonce , PK, SK) ->
    try
        enacl:box(Msg, Nonce, PK, SK)
    catch
        error:badarg -> badarg
    end.

box_open(CphText, Nonce, PK, SK) ->
    try
        enacl:box_open(CphText, Nonce, PK, SK)
    catch
         error:badarg -> badarg
    end.

failure(badarg) -> true;
failure(_) -> false.

prop_box_correct() ->
    ?FORALL({Msg, Nonce, {PK1, SK1}, {PK2, SK2}},
            {binary(),
             fault_rate(1, 40, nonce()),
             fault_rate(1, 40, keypair()),
             fault_rate(1, 40, keypair())},
        begin
            case nonce_valid(Nonce) andalso keypair_valid(PK1, SK1) andalso keypair_valid(PK2, SK2) of
                true ->
                    CipherText = enacl:box(Msg, Nonce, PK2, SK1),
                    {ok, DecodedMsg} = enacl:box_open(CipherText, Nonce, PK1, SK2),
                    equals(Msg, DecodedMsg);
                false ->
                    case box(Msg, Nonce, PK2, SK1) of
                        badarg -> true;
                        Res -> failure(box_open(Res, Nonce, PK1, SK2))
                    end
            end
        end).

prop_box_failure_integrity() ->
    ?FORALL({Msg, Nonce, {PK1, SK1}, {PK2, SK2}},
            {binary(),
             fault_rate(1, 40, nonce()),
             fault_rate(1, 40, keypair()),
             fault_rate(1, 40, keypair())},
        begin
            case nonce_valid(Nonce)
                 andalso keypair_valid(PK1, SK1)
                 andalso keypair_valid(PK2, SK2) of
                true ->
                    CipherText = enacl:box(Msg, Nonce, PK2, SK1),
                    Err = enacl:box_open([<<"x">>, CipherText], Nonce, PK1, SK2),
                    equals(Err, {error, failed_verification});
                false ->
                    case box(Msg, Nonce, PK2, SK1) of
                      badarg -> true;
                      Res ->
                        failure(box_open(Res, Nonce, PK1, SK2))
                    end
            end
        end).

%% SIGNATURES
%% ----------

prop_sign_keypair() ->
    ?FORALL(_D, return(dummy),
      begin
        #{ public := _, secret := _ } = enacl:sign_keypair(),
        true
      end).

sign_keypair_bad() ->
  ?LET(X, elements([pk, sk]),
    begin
      KP = enacl:sign_keypair(),
      case X of
        pk ->
          Sz = enacl:sign_keypair_public_size(),
          ?LET(Wrong, oneof([a, int(), ?SUCHTHAT(B, binary(), byte_size(B) /= Sz)]),
            KP#{ public := Wrong });
        sk ->
          Sz = enacl:sign_keypair_secret_size(),
          ?LET(Wrong, oneof([a, int(), ?SUCHTHAT(B, binary(), byte_size(B) /= Sz)]),
            KP#{ secret := Wrong })
      end
    end).

sign_keypair_good() ->
  return(enacl:sign_keypair()).

sign_keypair() ->
  fault(sign_keypair_bad(), sign_keypair_good()).

sign_keypair_public_valid(#{ public := Public })
  when is_binary(Public) ->
    byte_size(Public) == enacl:sign_keypair_public_size();
sign_keypair_public_valid(_) -> false.
    
sign_keypair_secret_valid(#{ secret := Secret })
  when is_binary(Secret) ->
    byte_size(Secret) == enacl:sign_keypair_secret_size();
sign_keypair_secret_valid(_) -> false.
    
sign_keypair_valid(KP) ->
  sign_keypair_public_valid(KP) andalso sign_keypair_secret_valid(KP).

prop_sign() ->
    ?FORALL({Msg, KeyPair}, {binary(), fault_rate(1, 40, sign_keypair())},
      begin
        case sign_keypair_secret_valid(KeyPair) of
          true ->
            #{ secret := Secret } = KeyPair,
            enacl:sign(Msg, Secret),
            true;
          false ->
            #{ secret := Secret } = KeyPair,
            badargs(fun() -> enacl:sign(Msg, Secret) end)
        end
      end).

signed_message_good(M) ->
    #{ public := PK, secret := SK} = enacl:sign_keypair(),
    SM = enacl:sign(M, SK),
    frequency([
        {3, return({{valid, SM}, PK})},
        {1, ?LET(X, elements([sm, pk]),
               case X of
                 sm -> {{invalid, binary(byte_size(SM))}, PK};
                 pk -> {{invalid, SM}, binary(byte_size(PK))}
               end)}]).

signed_message_bad() ->
    Sz = enacl:sign_keypair_public_size(),
    {binary(), oneof([a, int(), ?SUCHTHAT(B, binary(Sz), byte_size(B) /= Sz)])}.

signed_message(M) ->
    fault(signed_message_bad(), signed_message_good(M)).

signed_message_valid({valid, _}, _) -> true;
signed_message_valid({invalid, _}, _) -> true;
signed_message_valid(_, _) -> false.

prop_sign_open() ->
    ?FORALL(Msg, binary(),
      ?FORALL({SignMsg, PK}, signed_message(Msg),
          case signed_message_valid(SignMsg, PK) of
              true ->
                  case SignMsg of
                    {valid, SM} ->
                        equals({ok, Msg}, enacl:sign_open(SM, PK));
                    {invalid, SM} ->
                        equals({error, failed_verification}, enacl:sign_open(SM, PK))
                  end;
              false ->
                  badargs(fun() -> enacl:sign_open(SignMsg, PK) end)
          end)).
     
%% CRYPTO SECRET BOX
%% -------------------------------

%% Note: key sizes are the same in a lot of situations, so we can use the same generator
%% for keys in many locations.

key_sz(Sz) ->
  equals(enacl:secretbox_key_size(), Sz).

prop_key_sizes() ->
    conjunction([{secret, key_sz(enacl:secretbox_key_size())},
                 {stream, key_sz(enacl:stream_key_size())},
                 {auth, key_sz(enacl:auth_key_size())},
                 {onetimeauth, key_sz(enacl:onetime_auth_key_size())}]).

nonce_sz(Sz) ->
  equals(enacl:secretbox_nonce_size(), Sz).

prop_nonce_sizes() ->
    conjunction([{secret, nonce_sz(enacl:secretbox_nonce_size())},
                 {stream, nonce_sz(enacl:stream_nonce_size())}]).

secret_key_good() ->
	Sz = enacl:secretbox_key_size(),
	binary(Sz).

secret_key_bad() ->
	oneof([return(a),
	       nat(),
	       ?SUCHTHAT(B, binary(), byte_size(B) /= enacl:secretbox_key_size())]).

secret_key() ->
	fault(secret_key_bad(), secret_key_good()).

secret_key_valid(SK) when is_binary(SK) ->
	Sz = enacl:secretbox_key_size(),
	byte_size(SK) == Sz;
secret_key_valid(_SK) -> false.

secretbox(Msg, Nonce, Key) ->
  try
    enacl:secretbox(Msg, Nonce, Key)
  catch
    error:badarg -> badarg
  end.

secretbox_open(Msg, Nonce, Key) ->
  try
    enacl:secretbox_open(Msg, Nonce, Key)
  catch
    error:badarg -> badarg
  end.

prop_secretbox_correct() ->
    ?FORALL({Msg, Nonce, Key},
            {binary(),
             fault_rate(1, 40, nonce()),
             fault_rate(1, 40, secret_key())},
      begin
        case nonce_valid(Nonce) andalso secret_key_valid(Key) of
          true ->
             CipherText = enacl:secretbox(Msg, Nonce, Key),
             {ok, DecodedMsg} = enacl:secretbox_open(CipherText, Nonce, Key),
             equals(Msg, DecodedMsg);
          false ->
             case secretbox(Msg, Nonce, Key) of
               badarg -> true;
               Res ->
                 failure(secretbox_open(Res, Nonce, Key))
             end
        end
      end).

prop_secretbox_failure_integrity() ->
    ?FORALL({Msg, Nonce, Key}, {binary(), nonce(), secret_key()},
      begin
        CipherText = enacl:secretbox(Msg, Nonce, Key),
        Err = enacl:secretbox_open([<<"x">>, CipherText], Nonce, Key),
        equals(Err, {error, failed_verification})
      end).

%% CRYPTO STREAM
prop_stream_correct() ->
    ?FORALL({Len, Nonce, Key},
            {int(),
             fault_rate(1, 40, nonce()),
             fault_rate(1, 40, secret_key())},
        case Len >= 0 andalso nonce_valid(Nonce) andalso secret_key_valid(Key) of
          true ->
              CipherStream = enacl:stream(Len, Nonce, Key),
              equals(Len, byte_size(CipherStream));
          false ->
              badargs(fun() -> enacl:stream(Len, Nonce, Key) end)
        end).

prop_stream_xor_correct() ->
    ?FORALL({Msg, Nonce, Key},
            {binary(),
             fault_rate(1, 40, nonce()),
             fault_rate(1, 40, secret_key())},
        case nonce_valid(Nonce) andalso secret_key_valid(Key) of
            true ->
                CipherText = enacl:stream_xor(Msg, Nonce, Key),
                equals(Msg, enacl:stream_xor(CipherText, Nonce, Key));
            false ->
                badargs(fun() -> enacl:stream_xor(Msg, Nonce, Key) end)
        end).

%% CRYPTO AUTH
prop_auth_correct() ->
    ?FORALL({Msg, Key},
            {binary(),
             fault_rate(1, 40, secret_key())},
       case secret_key_valid(Key) of
         true ->
           Authenticator = enacl:auth(Msg, Key),
           equals(Authenticator, enacl:auth(Msg, Key));
         false ->
           badargs(fun() -> enacl:auth(Msg, Key) end)
       end).

authenticator_bad() ->
    oneof([a, int(), ?SUCHTHAT(X, binary(), byte_size(X) /= enacl:auth_size())]).

authenticator_good(Msg, Key) when is_binary(Key) ->
    Sz = enacl:secretbox_key_size(),
    case byte_size(Key) == Sz of
      true ->
        frequency([{1, ?LAZY({invalid, binary(enacl:auth_size())})},
                   {3, return({valid, enacl:auth(Msg, Key)})}]);
      false ->
        binary(enacl:auth_size())
    end;
authenticator_good(_Msg, _Key) ->
    binary(enacl:auth_size()).

authenticator(Msg, Key) ->
  fault(authenticator_bad(), authenticator_good(Msg, Key)).

authenticator_valid({valid, _}) -> true;
authenticator_valid({invalid, _}) -> true;
authenticator_valid(_) -> false.

prop_auth_verify_correct() ->
    ?FORALL({Msg, Key},
            {binary(),
             fault_rate(1, 40, secret_key())},
      ?FORALL(Authenticator, authenticator(Msg, Key),
        case secret_key_valid(Key) andalso authenticator_valid(Authenticator) of
          true ->
            case Authenticator of
              {valid, A} ->
                equals(true, enacl:auth_verify(A, Msg, Key));
              {invalid, A} ->
                equals(false, enacl:auth_verify(A, Msg, Key))
            end;
          false ->
            badargs(fun() -> enacl:auth_verify(Authenticator, Msg, Key) end)
        end)).

%% CRYPTO ONETIME AUTH
prop_onetimeauth_correct() ->
    ?FORALL({Msg, Key},
            {binary(),
             fault_rate(1, 40, secret_key())},
       case secret_key_valid(Key) of
         true ->
           Authenticator = enacl:onetime_auth(Msg, Key),
           equals(Authenticator, enacl:onetime_auth(Msg, Key));
         false ->
           badargs(fun() -> enacl:onetime_auth(Msg, Key) end)
       end).

ot_authenticator_bad() ->
    oneof([a, int(), ?SUCHTHAT(X, binary(), byte_size(X) /= enacl:onetime_auth_size())]).

ot_authenticator_good(Msg, Key) when is_binary(Key) ->
    Sz = enacl:secretbox_key_size(),
    case byte_size(Key) == Sz of
      true ->
        frequency([{1, ?LAZY({invalid, binary(enacl:onetime_auth_size())})},
                   {3, return({valid, enacl:onetime_auth(Msg, Key)})}]);
      false ->
        binary(enacl:onetime_auth_size())
    end;
ot_authenticator_good(_Msg, _Key) ->
    binary(enacl:auth_size()).

ot_authenticator(Msg, Key) ->
  fault(ot_authenticator_bad(), ot_authenticator_good(Msg, Key)).

ot_authenticator_valid({valid, _}) -> true;
ot_authenticator_valid({invalid, _}) -> true;
ot_authenticator_valid(_) -> false.

prop_onetime_auth_verify_correct() ->
    ?FORALL({Msg, Key},
            {binary(),
             fault_rate(1, 40, secret_key())},
      ?FORALL(Authenticator, ot_authenticator(Msg, Key),
        case secret_key_valid(Key) andalso ot_authenticator_valid(Authenticator) of
          true ->
            case Authenticator of
              {valid, A} ->
                equals(true, enacl:onetime_auth_verify(A, Msg, Key));
              {invalid, A} ->
                equals(false, enacl:onetime_auth_verify(A, Msg, Key))
            end;
          false ->
            badargs(fun() -> enacl:onetime_auth_verify(Authenticator, Msg, Key) end)
        end)).

%% HASHING
%% ---------------------------
diff_pair(Sz) ->
    ?SUCHTHAT({X, Y}, {g_binary(Sz), g_binary(Sz)},
        X /= Y).

prop_crypto_hash_eq() ->
    ?FORALL(Sz, oneof([1, 128, 1024, 1024*4]),
    ?FORALL(X, g_binary(Sz),
        case is_binary(X) of
          true -> equals(enacl:hash(X), enacl:hash(X));
          false ->
            try
              enacl:hash(X),
              false
            catch
              error:badarg -> true
            end
        end
    )).

prop_crypto_hash_neq() ->
    ?FORALL(Sz, oneof([1, 128, 1024, 1024*4]),
    ?FORALL({X, Y}, diff_pair(Sz),
        enacl:hash(X) /= enacl:hash(Y)
    )).

%% STRING COMPARISON
%% -------------------------

verify_pair_bad(Sz) ->
  ?LET(X, elements([fst, snd]),
    case X of
      fst ->
        {?SUCHTHAT(B, binary(), byte_size(B) /= Sz), binary(Sz)};
      snd ->
        {binary(Sz), ?SUCHTHAT(B, binary(), byte_size(B) /= Sz)}
    end).

verify_pair_good(Sz) ->
  oneof([
    ?LET(Bin, binary(Sz), {Bin, Bin}),
    ?SUCHTHAT({X, Y}, {binary(Sz), binary(Sz)}, X /= Y)]).

verify_pair(Sz) ->
  fault(verify_pair_bad(Sz), verify_pair_good(Sz)).

verify_pair_valid(Sz, X, Y) ->
    byte_size(X) == Sz andalso byte_size(Y) == Sz.

prop_verify_16() ->
    ?FORALL({X, Y}, verify_pair(16),
      case verify_pair_valid(16, X, Y) of
          true ->
              equals(X == Y, enacl:verify_16(X, Y));
          false ->
              try
                 enacl:verify_16(X, Y),
                 false
              catch
                  error:badarg -> true
              end
      end).

prop_verify_32() ->
    ?FORALL({X, Y}, verify_pair(32),
      case verify_pair_valid(32, X, Y) of
          true ->
              equals(X == Y, enacl:verify_32(X, Y));
          false ->
              try
                 enacl:verify_32(X, Y),
                 false
              catch
                  error:badarg -> true
              end
      end).

%% HELPERS
badargs(Thunk) ->
  try
    Thunk(),
    false
  catch
    error:badarg -> true
  end.
