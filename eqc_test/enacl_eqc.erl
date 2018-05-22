-module(enacl_eqc).
-include_lib("eqc/include/eqc.hrl").
-compile(export_all).

-ifndef(mini).
-compile({parse_transform, eqc_parallelize}).
-define(FAULT(Arg1, Arg2), fault(Arg1, Arg2)).
-define(FAULT_RATE(Arg1, Arg2, Arg3), fault_rate(Arg1, Arg2, Arg3)).
-else.
-define(FAULT(Arg1, Arg2), noop_fault(Arg1, Arg2)).
-define(FAULT_RATE(Arg1, Arg2, Arg3), noop_fault_rate(Arg1, Arg2, Arg3)).
-endif.

start()->
  eqc:module(?MODULE).

noop_fault(_Bad, Good) -> Good.

noop_fault_rate(_1, _2, Gen) -> Gen.

non_byte_int() ->
    oneof([
        ?LET(N, nat(), -(N+1)),
        ?LET(N, nat(), N+256)
    ]).

g_iolist() ->
    ?SIZED(Sz, g_iolist(Sz)).

g_iolist(0) ->
    ?FAULT(
        oneof([
          elements([a,b,c]),
          real(),
          non_byte_int()
        ]),
        return([]));
g_iolist(N) ->
    ?FAULT(
        oneof([
          elements([a,b,c]),
          real(),
          non_byte_int()
        ]),
        frequency([
            {1, g_iolist(0)},
            {N, ?LAZY(list(oneof([char(), binary(), g_iolist(N div 4)])))}
        ])).

g_iodata() ->
    ?FAULT(
      oneof([elements([a,b,c]), real()]),
      oneof([binary(), g_iolist(), eqc_gen:largebinary(64*1024)])).

v_iolist([]) -> true;
v_iolist([B|Xs]) when is_binary(B) -> v_iolist(Xs);
v_iolist([C|Xs]) when is_integer(C), C >= 0, C < 256 -> v_iolist(Xs);
v_iolist([L|Xs]) when is_list(L) ->
    v_iolist(L) andalso v_iolist(Xs);
v_iolist(_) -> false.

v_iodata(B) when is_binary(B) -> true;
v_iodata(Structure) -> v_iolist(Structure).

%% Generator for binaries of a given size with different properties and fault injection:
g_binary(Sz) ->
    ?FAULT(g_binary_bad(Sz), g_binary_good(Sz)).

g_binary_good(Sz) when Sz =< 32 -> binary(Sz);
g_binary_good(Sz) -> eqc_gen:largebinary(Sz).

g_binary_bad(Sz) ->
    frequency([
        {5, ?SUCHTHAT(B, binary(), byte_size(B) /= Sz)},
        {1, elements([a, b])},
        {1, int()},
        {1, g_iodata()}
    ]).

v_binary(Sz, N) when is_binary(N) ->
    byte_size(N) == Sz;
v_binary(_, _) -> false.


%% Typical generators based on the binaries
nonce() -> g_binary(enacl:box_nonce_size()).
nonce_valid(N) -> v_binary(enacl:box_nonce_size(), N).

%% Generator of natural numbers
g_nat() ->
    ?FAULT(g_nat_bad(), nat()).

g_nat_bad() ->
    oneof([
        elements([a,b,c]),
        real(),
        binary(),
        ?LET(X, nat(), -X)
    ]).

is_nat(N) when is_integer(N), N >= 0 -> true;
is_nat(_) -> false.

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
    ?FAULT(keypair_bad(), keypair_good()).

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

box_seal(Msg, PK) ->
    try
        enacl:box_seal(Msg, PK)
    catch
       error:badarg -> badarg
    end.

box_seal_open(Cph, PK, SK) ->
    try
        enacl:box_seal_open(Cph, PK, SK)
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
failure({error, failed_verification}) -> true;
failure(X) -> {failure, X}.

prop_box_correct() ->
    ?FORALL({Msg, Nonce, {PK1, SK1}, {PK2, SK2}},
            {?FAULT_RATE(1, 40, g_iodata()),
             ?FAULT_RATE(1, 40, nonce()),
             ?FAULT_RATE(1, 40, keypair()),
             ?FAULT_RATE(1, 40, keypair())},
        begin
            case v_iodata(Msg) andalso nonce_valid(Nonce) andalso keypair_valid(PK1, SK1) andalso keypair_valid(PK2, SK2) of
                true ->
                    Key = enacl:box_beforenm(PK2, SK1),
                    Key = enacl:box_beforenm(PK1, SK2),
                    CipherText = enacl:box(Msg, Nonce, PK2, SK1),
                    CipherText = enacl:box_afternm(Msg, Nonce, Key),
                    {ok, DecodedMsg} = enacl:box_open(CipherText, Nonce, PK1, SK2),
                    {ok, DecodedMsg} = enacl:box_open_afternm(CipherText, Nonce, Key),
                    equals(iolist_to_binary(Msg), DecodedMsg);
                false ->
                    case box(Msg, Nonce, PK2, SK1) of
                        badarg -> true;
                        Res -> failure(box_open(Res, Nonce, PK1, SK2))
                    end
            end
        end).

prop_box_failure_integrity() ->
    ?FORALL({Msg, Nonce, {PK1, SK1}, {PK2, SK2}},
            {?FAULT_RATE(1, 40, g_iodata()),
             ?FAULT_RATE(1, 40, nonce()),
             ?FAULT_RATE(1, 40, keypair()),
             ?FAULT_RATE(1, 40, keypair())},
        begin
            case v_iodata(Msg)
                 andalso nonce_valid(Nonce)
                 andalso keypair_valid(PK1, SK1)
                 andalso keypair_valid(PK2, SK2) of
                true ->
                    Key = enacl:box_beforenm(PK2, SK1),
                    CipherText = enacl:box(Msg, Nonce, PK2, SK1),
                    Err = enacl:box_open([<<"x">>, CipherText], Nonce, PK1, SK2),
                    Err = enacl:box_open_afternm([<<"x">>, CipherText], Nonce, Key),
                    equals(Err, {error, failed_verification});
                false ->
                    case box(Msg, Nonce, PK2, SK1) of
                      badarg -> true;
                      Res ->
                        failure(box_open(Res, Nonce, PK1, SK2))
                    end
            end
        end).
        
prop_seal_box_failure_integrity() ->
    ?FORALL({Msg, {PK1, SK1}}, {?FAULT_RATE(1,40,g_iodata()), ?FAULT_RATE(1,40,keypair())},
      begin
         case v_iodata(Msg) andalso keypair_valid(PK1, SK1) of
           true ->
             CT = enacl:box_seal(Msg, PK1),
             Err = enacl:box_seal_open([<<"x">>, CT], PK1, SK1),
             equals(Err, {error, failed_verification});
           false ->
             case box_seal(Msg, PK1) of
                 badarg -> true;
                 Res ->
                    failure(box_seal_open(Res, PK1, SK1))
            end
        end
    end).

prop_seal_box_correct() ->
    ?FORALL({Msg, {PK1, SK1}},
        {?FAULT_RATE(1, 40, g_iodata()),
         ?FAULT_RATE(1, 40, keypair())},
     begin
         case v_iodata(Msg) andalso keypair_valid(PK1, SK1) of
             true ->
                 SealedCipherText = enacl:box_seal(Msg, PK1),
                 {ok, DecodedMsg} = enacl:box_seal_open(SealedCipherText, PK1, SK1),
                 equals(iolist_to_binary(Msg), DecodedMsg);
             false ->
                case box_seal(Msg, PK1) of
                    badarg -> true;
                    Res -> failure(box_seal_open(Res, PK1, SK1))
                end
         end
     end).

%% PRECOMPUTATIONS
beforenm_key() ->
    ?LET([{PK1, SK1}, {PK2, SK2}], [?FAULT_RATE(1, 40, keypair()), ?FAULT_RATE(1, 40, keypair())],
        case keypair_valid(PK1, SK1) andalso keypair_valid(PK2, SK2) of
            true ->
                enacl:box_beforenm(PK1, SK2);
            false ->
                oneof([
                  elements([a,b,c]),
                  real(),
                  ?SUCHTHAT(X, binary(), byte_size(X) /= enacl:box_beforenm_bytes())
                  ])
        end).

v_key(K) when is_binary(K) -> byte_size(K) == enacl:box_beforenm_bytes();
v_key(_) -> false.

prop_beforenm_correct() ->
    ?FORALL([{PK1, SK1}, {PK2, SK2}], [?FAULT_RATE(1, 40, keypair()), ?FAULT_RATE(1, 40, keypair())],
        case keypair_valid(PK1, SK1) andalso keypair_valid(PK2, SK2) of
            true ->
                equals(enacl:box_beforenm(PK1, SK2), enacl:box_beforenm(PK2, SK1));
            false ->
                badargs(fun() ->
                	K = enacl:box_beforenm(PK1, SK2),
                	K = enacl:box_beforenm(PK2, SK1)
                end)
        end).

prop_afternm_correct() ->
    ?FORALL([Msg, Nonce, Key],
        [?FAULT_RATE(1, 40, g_iodata()),
         ?FAULT_RATE(1, 40, nonce()),
         ?FAULT_RATE(1, 40, beforenm_key())],
      begin
          case v_iodata(Msg) andalso nonce_valid(Nonce) andalso v_key(Key) of
              true ->
                  CipherText = enacl:box_afternm(Msg, Nonce, Key),
                  equals({ok, iolist_to_binary(Msg)}, enacl:box_open_afternm(CipherText, Nonce, Key));
              false ->
                  try enacl:box_afternm(Msg, Nonce, Key) of
                      CipherText ->
                          try enacl:box_open_afternm(CipherText, Nonce, Key) of
                              {ok, _M} -> false;
                              {error, failed_validation} -> false
                          catch
                              error:badarg -> true
                          end
                  catch
                      error:badarg -> true
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
  ?FAULT(sign_keypair_bad(), sign_keypair_good()).

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

prop_sign_detached() ->
    ?FORALL({Msg, KeyPair},
        {?FAULT_RATE(1, 40, g_iodata()),
         ?FAULT_RATE(1, 40, sign_keypair())},
      begin
          case v_iodata(Msg) andalso sign_keypair_secret_valid(KeyPair) of
            true ->
                #{ secret := Secret } = KeyPair,
                enacl:sign_detached(Msg, Secret),
                true;
            false ->
                #{ secret := Secret } = KeyPair,
                badargs(fun() -> enacl:sign_detached(Msg, Secret) end)
          end
      end).

prop_sign() ->
    ?FORALL({Msg, KeyPair},
          {?FAULT_RATE(1, 40, g_iodata()),
           ?FAULT_RATE(1, 40, sign_keypair())},
      begin
        case v_iodata(Msg) andalso sign_keypair_secret_valid(KeyPair) of
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

signed_message_good_d(M) ->
    #{ public := PK, secret := SK} = enacl:sign_keypair(),
    Sig = enacl:sign_detached(M, SK),
    frequency([
        {3, return({{valid, Sig}, PK})},
        {1, ?LET(X, elements([sm, pk]),
               case X of
                 sm -> {{invalid, binary(byte_size(Sig))}, PK};
                 pk -> {{invalid, Sig}, binary(byte_size(PK))}
               end)}]).

signed_message_bad() ->
    Sz = enacl:sign_keypair_public_size(),
    {binary(), oneof([a, int(), ?SUCHTHAT(B, binary(Sz), byte_size(B) /= Sz)])}.

signed_message_bad_d() ->
    Sz = enacl:sign_keypair_public_size(),
    {binary(), oneof([a, int(), ?SUCHTHAT(B, binary(Sz), byte_size(B) /= Sz)])}.

signed_message(M) ->
    ?FAULT(signed_message_bad(), signed_message_good(M)).

signed_message_d(M) ->
    ?FAULT(signed_message_bad(), signed_message_good(M)).

signed_message_valid({valid, _}, _) -> true;
signed_message_valid({invalid, _}, _) -> true;
signed_message_valid(_, _) -> false.

prop_sign_detached_open() ->
    ?FORALL(Msg, g_iodata(),
      ?FORALL({SignMsg, PK}, signed_message_d(Msg),
          case v_iodata(Msg) andalso signed_message_valid(SignMsg, PK) of
              true ->
                  case SignMsg of
                    {valid, Sig} ->
                        equals({ok, Msg}, enacl:sign_verify_detached(Sig, Msg, PK));
                    {invalid, Sig} ->
                        equals({error, failed_verification}, enacl:sign_verify_detached(Sig, Msg, PK))
                  end;
              false ->
                  badargs(fun() -> enacl:sign_verify_detached(SignMsg, Msg, PK) end)
          end)).

prop_sign_open() ->
    ?FORALL(Msg, g_iodata(),
      ?FORALL({SignMsg, PK}, signed_message(Msg),
          case v_iodata(Msg) andalso signed_message_valid(SignMsg, PK) of
              true ->
                  case SignMsg of
                    {valid, SM} ->
                        equals({ok, iolist_to_binary(Msg)}, enacl:sign_open(SM, PK));
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

%% prop_key_sizes() ->
%%     conjunction([{secret, key_sz(enacl:secretbox_key_size())},
%%                  {stream, key_sz(enacl:stream_key_size())},
%%                  {auth, key_sz(enacl:auth_key_size())},
%%                  {onetimeauth, key_sz(enacl:onetime_auth_key_size())}]).

nonce_sz(Sz) ->
  equals(enacl:secretbox_nonce_size(), Sz).

%% prop_nonce_sizes() ->
%%     conjunction([{secret, nonce_sz(enacl:secretbox_nonce_size())},
%%                  {stream, nonce_sz(enacl:stream_nonce_size())}]).

secret_key_good() ->
	Sz = enacl:secretbox_key_size(),
	binary(Sz).

secret_key_bad() ->
	oneof([return(a),
	       nat(),
	       ?SUCHTHAT(B, binary(), byte_size(B) /= enacl:secretbox_key_size())]).

secret_key() ->
	?FAULT(secret_key_bad(), secret_key_good()).

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
            {?FAULT_RATE(1, 40, g_iodata()),
             ?FAULT_RATE(1, 40, nonce()),
             ?FAULT_RATE(1, 40, secret_key())},
      begin
        case v_iodata(Msg) andalso nonce_valid(Nonce) andalso secret_key_valid(Key) of
          true ->
             CipherText = enacl:secretbox(Msg, Nonce, Key),
             {ok, DecodedMsg} = enacl:secretbox_open(CipherText, Nonce, Key),
             equals(iolist_to_binary(Msg), DecodedMsg);
          false ->
             case secretbox(Msg, Nonce, Key) of
               badarg -> true;
               Res ->
                 failure(secretbox_open(Res, Nonce, Key))
             end
        end
      end).

prop_secretbox_failure_integrity() ->
    ?FORALL({Msg, Nonce, Key}, {g_iodata(), nonce(), secret_key()},
      begin
        CipherText = enacl:secretbox(Msg, Nonce, Key),
        Err = enacl:secretbox_open([<<"x">>, CipherText], Nonce, Key),
        equals(Err, {error, failed_verification})
      end).

%% CRYPTO STREAM
prop_stream_correct() ->
    ?FORALL({Len, Nonce, Key},
            {int(),
             ?FAULT_RATE(1, 40, nonce()),
             ?FAULT_RATE(1, 40, secret_key())},
        case Len >= 0 andalso nonce_valid(Nonce) andalso secret_key_valid(Key) of
          true ->
              CipherStream = enacl:stream(Len, Nonce, Key),
              equals(Len, byte_size(CipherStream));
          false ->
              badargs(fun() -> enacl:stream(Len, Nonce, Key) end)
        end).

xor_bytes(<<A, As/binary>>, <<B, Bs/binary>>) ->
    [A bxor B | xor_bytes(As, Bs)];
xor_bytes(<<>>, <<>>) -> [].

%% prop_stream_xor_correct() ->
%%     ?FORALL({Msg, Nonce, Key},
%%             {?FAULT_RATE(1, 40, g_iodata()),
%%              ?FAULT_RATE(1, 40, nonce()),
%%              ?FAULT_RATE(1, 40, secret_key())},
%%         case v_iodata(Msg) andalso nonce_valid(Nonce) andalso secret_key_valid(Key) of
%%             true ->
%%                 Stream = enacl:stream(iolist_size(Msg), Nonce, Key),
%%                 CipherText = enacl:stream_xor(Msg, Nonce, Key),
%%                 StreamXor = enacl:stream_xor(CipherText, Nonce, Key),
%%                 conjunction([
%%                     {'xor', equals(iolist_to_binary(Msg), StreamXor)},
%%                     {stream, equals(iolist_to_binary(xor_bytes(Stream, iolist_to_binary(Msg))), CipherText)}
%%                 ]);
%%             false ->
%%                 badargs(fun() -> enacl:stream_xor(Msg, Nonce, Key) end)
%%         end).

%% CRYPTO AUTH
prop_auth_correct() ->
    ?FORALL({Msg, Key},
            {?FAULT_RATE(1, 40, g_iodata()),
             ?FAULT_RATE(1, 40, secret_key())},
       case v_iodata(Msg) andalso secret_key_valid(Key) of
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
    case v_iodata(Msg) andalso byte_size(Key) == Sz of
      true ->
        frequency([{1, ?LAZY({invalid, binary(enacl:auth_size())})},
                   {3, return({valid, enacl:auth(Msg, Key)})}]);
      false ->
        binary(enacl:auth_size())
    end;
authenticator_good(_Msg, _Key) ->
    binary(enacl:auth_size()).

authenticator(Msg, Key) ->
  ?FAULT(authenticator_bad(), authenticator_good(Msg, Key)).

authenticator_valid({valid, _}) -> true;
authenticator_valid({invalid, _}) -> true;
authenticator_valid(_) -> false.

prop_auth_verify_correct() ->
    ?FORALL({Msg, Key},
            {?FAULT_RATE(1, 40, g_iodata()),
             ?FAULT_RATE(1, 40, secret_key())},
      ?FORALL(Authenticator, authenticator(Msg, Key),
        case v_iodata(Msg) andalso secret_key_valid(Key) andalso authenticator_valid(Authenticator) of
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
            {?FAULT_RATE(1, 40, g_iodata()),
             ?FAULT_RATE(1, 40, secret_key())},
       case v_iodata(Msg) andalso secret_key_valid(Key) of
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
    case v_iodata(Msg) andalso byte_size(Key) == Sz of
      true ->
        frequency([{1, ?LAZY({invalid, binary(enacl:onetime_auth_size())})},
                   {3, return({valid, enacl:onetime_auth(Msg, Key)})}]);
      false ->
        binary(enacl:onetime_auth_size())
    end;
ot_authenticator_good(_Msg, _Key) ->
    binary(enacl:auth_size()).

ot_authenticator(Msg, Key) ->
  ?FAULT(ot_authenticator_bad(), ot_authenticator_good(Msg, Key)).

ot_authenticator_valid({valid, _}) -> true;
ot_authenticator_valid({invalid, _}) -> true;
ot_authenticator_valid(_) -> false.

prop_onetime_auth_verify_correct() ->
    ?FORALL({Msg, Key},
            {?FAULT_RATE(1, 40, g_iodata()),
             ?FAULT_RATE(1, 40, secret_key())},
      ?FORALL(Authenticator, ot_authenticator(Msg, Key),
        case v_iodata(Msg) andalso secret_key_valid(Key) andalso ot_authenticator_valid(Authenticator) of
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
diff_pair() ->
    ?SUCHTHAT({X, Y}, {g_iodata(), g_iodata()},
        iolist_to_binary(X) /= iolist_to_binary(Y)).

prop_crypto_hash_eq() ->
    ?FORALL(X, g_iodata(),
        case v_iodata(X) of
          true -> equals(enacl:hash(X), enacl:hash(X));
          false ->
            try
              enacl:hash(X),
              false
            catch
              error:badarg -> true
            end
        end
    ).

prop_crypto_hash_neq() ->
    ?FORALL({X, Y}, diff_pair(),
        enacl:hash(X) /= enacl:hash(Y)
    ).

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
  ?FAULT(verify_pair_bad(Sz), verify_pair_good(Sz)).

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

%% RANDOMBYTES
prop_randombytes() ->
    ?FORALL(X, g_nat(),
        case is_nat(X) of
            true ->
                is_binary(enacl:randombytes(X));
            false ->
                try
                    enacl:randombytes(X),
                    false
                catch
                    error:badarg ->
                       true
                end
       end).

%% RANDOMINT/0
prop_randomint() ->
    ?FORALL(X, g_nat(),
        case is_nat(X) of
            true ->
                is_nat(enacl:randomint());
            false ->
		true
       end).

%% RANDOMINT/1
prop_randomint_bounds() ->
    ?FORALL(X, g_nat(),
        case X > 0 of
            true ->
		R = enacl:randomint(X),		
                is_nat(R) andalso (R < X);
            false ->
		true
       end).

%% RANDOMINT/2
prop_randomint_range() ->
    ?FORALL({A,B}, {g_nat(),g_nat()},
	    case is_nat(A) andalso is_nat(B) > 0 of
		true ->			
		    case B >= A of
			true ->
			    R = enacl:randomint(A,B),		
			    is_nat(R) andalso (R >= A) andalso (R =< B);
			false ->
			    try
				enacl:randomint(A,B)
			    catch
				error:badarg ->
				    true
			    end
		    end;		    
		false  ->
		    true
	    end).

%% SCRAMBLING
prop_scramble_block() ->
    ?FORALL({Block, Key}, {binary(16), eqc_gen:largebinary(32)},
        is_binary(enacl_ext:scramble_block_16(Block, Key))).

%% HELPERS
badargs(Thunk) ->
  try
    Thunk(),
    false
  catch
    error:badarg -> true
  end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Joel Test Blobs

test_basic_signing() ->
  #{ public := PK0, secret := SK0 } = enacl:sign_keypair(),
  #{ public := PK1, secret := SK1 } = enacl:sign_keypair(),
  MSG0 = <<"This is super s3Kr3t, srsly!">>,
  [
    %% (+) Sign and open using valid keypair
    case enacl:sign_open(enacl:sign(MSG0, SK0), PK0) of
        {ok,MSG1} -> MSG0==MSG1;
        _         -> false
    end
  , %% (-) Sign and open using invalid keypair
    case enacl:sign_open(enacl:sign(MSG0, SK0), PK1) of
        {error,failed_verification} -> true;
        _                           -> false
    end
  , %% (+) Detached mode sig and verify
    { enacl:sign_verify_detached(enacl:sign_detached(MSG0, SK0), MSG0, PK0)
    , enacl:sign_verify_detached(enacl:sign_detached(MSG0, SK1), MSG0, PK1)
    }
  , %% (-) Incorrect sigs/PKs/messages given during verify
    { false == enacl:sign_verify_detached(enacl:sign_detached(MSG0, SK0), MSG0, PK1)
    , false == enacl:sign_verify_detached(enacl:sign_detached(MSG0, SK1), MSG0, PK0)
    , false == enacl:sign_verify_detached(enacl:sign_detached(MSG0, SK0), <<"bzzt">>, PK0)
    }
  ].
