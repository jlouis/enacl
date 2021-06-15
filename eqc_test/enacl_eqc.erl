-module(enacl_eqc).
-include_lib("eqc/include/eqc.hrl").
-compile([export_all, nowarn_export_all]).

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
nonce() -> g_binary(enacl:box_NONCEBYTES()).
nonce_valid(N) -> v_binary(enacl:box_NONCEBYTES(), N).

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
              PKBytes = enacl:box_PUBLICKEYBYTES(),
              {oneof([return(a), nat(), ?SUCHTHAT(B, binary(), byte_size(B) /= PKBytes)]), SK};
            sk ->
              SKBytes = enacl:box_SECRETKEYBYTES(),
              {PK, oneof([return(a), nat(), ?SUCHTHAT(B, binary(), byte_size(B) /= SKBytes)])}
        end
      end).

keypair() ->
    ?FAULT(keypair_bad(), keypair_good()).

kx_keypair_good() ->
  #{ public := PK, secret := SK} = enacl:kx_keypair(),
  {PK, SK}.

kx_keypair_bad() ->
  ?LET(X, elements([pk, sk]),
  begin
    #{ public := PK, secret := SK} = enacl:box_keypair(),
    case X of
      pk ->
        PKBytes = enacl:kx_public_key_size(),
        {oneof([return(a), nat(), ?SUCHTHAT(B, binary(), byte_size(B) /= PKBytes)]), SK};
      sk ->
        SKBytes = enacl:kx_secret_key_size(),
        {PK, oneof([return(a), nat(), ?SUCHTHAT(B, binary(), byte_size(B) /= SKBytes)])}
    end
  end).

g_generichash_data() ->
  binary().

g_generichash_key() ->
  ?LET({Min, Max}, {return(enacl_nif:crypto_generichash_KEYBYTES_MIN()), return(enacl_nif:crypto_generichash_KEYBYTES_MAX())},
    largebinary({limit, Min, Max})).

g_generichash_size() ->
  ?LET({Min, Max}, {return(enacl_nif:crypto_generichash_BYTES_MIN()), return(enacl_nif:crypto_generichash_BYTES_MAX())},
    choose(Min, Max)).

%% CRYPTO BOX
%% ---------------------------
%% * box/4
%% * box_open/4
%% * box_beforenm/2
%% * box_afternm/3
%% * box_open_afternm/3
keypair_valid(PK, SK) when is_binary(PK), is_binary(SK) ->
    PKBytes = enacl:box_PUBLICKEYBYTES(),
    SKBytes = enacl:box_SECRETKEYBYTES(),
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
                  ?SUCHTHAT(X, binary(), byte_size(X) /= enacl:box_BEFORENMBYTES())
                  ])
        end).

v_key(K) when is_binary(K) -> byte_size(K) == enacl:box_BEFORENMBYTES();
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
          Sz = enacl:sign_PUBLICBYTES(),
          ?LET(Wrong, oneof([a, int(), ?SUCHTHAT(B, binary(), byte_size(B) /= Sz)]),
            KP#{ public := Wrong });
        sk ->
          Sz = enacl:sign_SECRETBYTES(),
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
    byte_size(Public) == enacl:sign_PUBLICBYTES();
sign_keypair_public_valid(_) -> false.

sign_keypair_secret_valid(#{ secret := Secret })
  when is_binary(Secret) ->
    byte_size(Secret) == enacl:sign_SECRETBYTES();
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
    Sz = enacl:sign_PUBLICBYTES(),
    {binary(), oneof([a, int(), ?SUCHTHAT(B, binary(Sz), byte_size(B) /= Sz)])}.

signed_message_bad_d() ->
    Sz = enacl:sign_PUBLICBYTES(),
    {binary(), oneof([a, int(), ?SUCHTHAT(B, binary(Sz), byte_size(B) /= Sz)])}.

signed_message(M) ->
    ?FAULT(signed_message_bad(), signed_message_good(M)).

signed_message_d(M) ->
    ?FAULT(signed_message_bad_d(), signed_message_good_d(M)).

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
                        equals(true, enacl:sign_verify_detached(Sig, Msg, PK));
                    {invalid, Sig} ->
                        equals(false, enacl:sign_verify_detached(Sig, Msg, PK))
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


%% CRYPTO SECRET BOX
%% ------------------------------------------------------------
%% * secretbox/3
%% * secretbo_open/3
secret_key_good() ->
	Sz = enacl:secretbox_KEYBYTES(),
	binary(Sz).

secret_key_bad() ->
	oneof([return(a),
	       nat(),
	       ?SUCHTHAT(B, binary(), byte_size(B) /= enacl:secretbox_KEYBYTES())]).

secret_key() ->
	?FAULT(secret_key_bad(), secret_key_good()).

secret_key_valid(SK) when is_binary(SK) ->
	Sz = enacl:secretbox_KEYBYTES(),
	byte_size(SK) == Sz;
secret_key_valid(_SK) -> false.

secretbox(Msg, Nonce, Key) ->
  try enacl:secretbox(Msg, Nonce, Key)
  catch error:badarg -> badarg
  end.

secretbox_open(Msg, Nonce, Key) ->
  try enacl:secretbox_open(Msg, Nonce, Key)
  catch error:badarg -> badarg
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

%% AEAD ChaCha20Poly1305
%% ------------------------------------------------------------
%% * aead_chacha20poly1305_encrypt/4,
%% * aead_chacha20poly1305_decrypt/4,
prop_aead_chacha20poly1305_ietf() ->
  NPubBytes = enacl:aead_chacha20poly1305_ietf_NPUBBYTES(),
  ?FORALL({Key, Msg, AD, Nonce},
          {binary(32), binary(), ?LET(ADBytes, choose(0,16), binary(ADBytes)), binary(NPubBytes)},
  begin
    EncryptMsg = enacl:aead_chacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key),
    equals(enacl:aead_chacha20poly1305_ietf_decrypt(EncryptMsg, AD, Nonce, Key), Msg)
  end).

prop_aead_chacha20poly1305_ietf_fail() ->
  NPubBytes = enacl:aead_chacha20poly1305_ietf_NPUBBYTES(),
  ?FORALL({Key, Msg, AD, Nonce},
          {binary(32), binary(), ?LET(ADBytes, choose(0,16), binary(ADBytes)), binary(NPubBytes)},
  begin
    EncryptMsg = enacl:aead_chacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key),
    case enacl:aead_chacha20poly1305_ietf_decrypt(<<0:8, EncryptMsg/binary>>, AD, Nonce, Key) of
        {error, _} -> true;
        _          -> false
    end
  end).

%% * aead_xchacha20poly1305_encrypt/4,
%% * aead_xchacha20poly1305_decrypt/4,
prop_aead_xchacha20poly1305_ietf() ->
  NPubBytes = enacl:aead_xchacha20poly1305_ietf_NPUBBYTES(),
  ?FORALL({Key, Msg, AD, Nonce},
          {binary(32), binary(), ?LET(ADBytes, choose(0,16), binary(ADBytes)), binary(NPubBytes)},
  begin
    EncryptMsg = enacl:aead_xchacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key),
    equals(enacl:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, AD, Nonce, Key), Msg)
  end).

prop_aead_xchacha20poly1305_ietf_fail() ->
  NPubBytes = enacl:aead_xchacha20poly1305_ietf_NPUBBYTES(),
  ?FORALL({Key, Msg, AD, Nonce},
          {binary(32), binary(), ?LET(ADBytes, choose(0,16), binary(ADBytes)), binary(NPubBytes)},
  begin
    EncryptMsg = enacl:aead_xchacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key),
    case enacl:aead_xchacha20poly1305_ietf_decrypt(<<0:8, EncryptMsg/binary>>, AD, Nonce, Key) of
        {error, _} -> true;
        _          -> false
    end
  end).

%% CRYPTO STREAM
%% ------------------------------------------------------------
%% * stream/3
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

positive() ->
  ?LET(N, nat(), N+1).

chacha20_nonce() ->
  Sz = enacl:stream_chacha20_NONCEBYTES(),
  binary(Sz).

chacha20_key() ->
  Sz = enacl:stream_chacha20_KEYBYTES(),
  binary(Sz).

prop_stream_chacha20_correct() ->
  ?FORALL(Len, positive(),
    ?FORALL({Msg, Nonce, Key}, {binary(Len), chacha20_nonce(), chacha20_key()},
      begin
        CT = enacl:stream_chacha20_xor(Msg, Nonce, Key),
        Stream = enacl:stream_chacha20(Len, Nonce, Key),
        CT2 = list_to_binary(xor_bytes(Stream, Msg)),
        equals(CT, CT2)
      end)).

%% CRYPTO AUTH
%% ------------------------------------------------------------
%% * auth/2
%% * auth_verify/3
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
    oneof([a, int(), ?SUCHTHAT(X, binary(), byte_size(X) /= enacl:auth_BYTES())]).

authenticator_good(Msg, Key) when is_binary(Key) ->
    Sz = enacl:secretbox_KEYBYTES(),
    case v_iodata(Msg) andalso byte_size(Key) == Sz of
      true ->
        frequency([{1, ?LAZY({invalid, binary(enacl:auth_BYTES())})},
                   {3, return({valid, enacl:auth(Msg, Key)})}]);
      false ->
        binary(enacl:auth_BYTES())
    end;
authenticator_good(_Msg, _Key) ->
    binary(enacl:auth_BYTES()).

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
%% ------------------------------------------------------------
%% * onetime_auth/2
%% * onetime_auth_verify/3
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
    oneof([a, int(), ?SUCHTHAT(X, binary(), byte_size(X) /= enacl:onetime_auth_BYTES())]).

ot_authenticator_good(Msg, Key) when is_binary(Key) ->
    Sz = enacl:secretbox_KEYBYTES(),
    case v_iodata(Msg) andalso byte_size(Key) == Sz of
      true ->
        frequency([{1, ?LAZY({invalid, binary(enacl:onetime_auth_BYTES())})},
                   {3, return({valid, enacl:onetime_auth(Msg, Key)})}]);
      false ->
        binary(enacl:onetime_auth_BYTES())
    end;
ot_authenticator_good(_Msg, _Key) ->
    binary(enacl:auth_BYTES()).

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

%% PWHASH
%% -------------------------------
%% * pwhash/2
%% * pwhash_str/1
%% * pwhash_str_verify/2
pwhash(Passwd, Salt) ->
  try
    enacl:pwhash(Passwd, Salt)
  catch
    error:badarg -> badarg
  end.

pwhash(Password, Salt, Ops, Mem, Alg) ->
  try
    enacl:pwhsah(Password, Salt, Ops, Mem, Alg)
  catch
    error:badarg -> badarg
  end.

pwhash_str(Passwd) ->
  try
    enacl:pwhash_str(Passwd)
  catch
    error:badarg -> badarg
  end.

pwhash_str_verify(PasswdHash, Passwd) ->
  try
    enacl:pwhash_str_verify(PasswdHash, Passwd)
  catch
    error:badarg -> badarg
  end.

prop_pwhash() ->
  ?FORALL({Password, Salt, OLimit, MLimit, Alg},
          {binary(16),
           binary(16),
           elements([interactive, moderate]), %% These could add senstitive, but are too runtime-expensive
           elements([interactive, moderate]), %% And that is for a reason.
           elements([default, 'argon2id13'])}, %% Argon2I13 uses different limits, so it is kept out as
                                               %% this would otherwise fail
    begin
       Bin1 = enacl:pwhash(Password, Salt, OLimit, MLimit, Alg),
       Bin2 = enacl:pwhash(Password, Salt, OLimit, MLimit, Alg),
       equals(Bin1, Bin2)
    end).

prop_pwhash_str_verify() ->
    ?FORALL({Passwd, OLimit, MLimit},
            {?FAULT_RATE(1, 40, g_iodata()),
             elements([interactive, moderate]),
             elements([interactive, moderate])},
            begin
                case v_iodata(Passwd) of
                    true ->
                        Ascii = enacl:pwhash_str(Passwd, OLimit, MLimit),
                        S = enacl:pwhash_str_verify(Ascii, Passwd),
                        equals(S, true);
                    false ->
                        badargs(fun() -> enacl:pwhash_str(Passwd) end),
                        badargs(fun() -> enacl:pwhash_str_verify("", Passwd) end)
                end
            end).

%% SUBTLE HASHING
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

prop_crypto_shorthash_eq() ->
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
prop_crypto_generichash_eq() ->
  ?FORALL({Sz, X, Key}, {g_generichash_size(), g_generichash_data(), g_generichash_key()},
      equals(enacl:generichash(Sz, X, Key), enacl:generichash(Sz, X, Key))).

generichash_loop(S, []) -> S;
generichash_loop(S, [M|Ms]) ->
  S2 = enacl:generichash_update(S, M),
  generichash_loop(S2, Ms).

prop_crypto_generichash_multi_part_eq() ->
  ?FORALL({Sz, Xs, Key}, {g_generichash_size(), list(g_generichash_data()), g_generichash_key()},
  begin
    S1 = generichash_loop(enacl:generichash_init(Sz, Key), Xs),
    S2 = generichash_loop(enacl:generichash_init(Sz, Key), Xs),
    equals(enacl:generichash_final(S1), enacl:generichash_final(S2))
  end).

prop_crypto_shorthash_neq() ->
  ?FORALL({X, Y}, diff_pair(),
    enacl:hash(X) /= enacl:hash(Y)
  ).

%% STRING COMPARISON
%% -------------------------
%% * verify_16/2,
%% * verify_32/2
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
%% ------------------------------------------------------------
%% * randombytes/1
prop_randombytes() ->
    ?FORALL(X, g_nat(),
        case is_nat(X) of
            true ->
              R = enacl:randombytes(X),
              is_binary(R) andalso (byte_size(R) == X);
            false ->
                try
                    enacl:randombytes(X),
                    false
                catch
                    error:badarg ->
                       true
                end
       end).

prop_randombytes_uint32() ->
  ?FORALL(_, return(x),
    begin
      V = enacl:randombytes_uint32(),
      is_integer(V)
    end).

%% KX
%% ---------------------------
prop_kx() ->
  ?FORALL({{CPK, CSK}, {SPK, SSK}}, {kx_keypair_good(), kx_keypair_good()},
  begin
    #{ client_tx := CTX, client_rx := CRX} = enacl:kx_client_session_keys(CPK, CSK, SPK),
    #{ server_tx := STX, server_rx := SRX} = enacl:kx_server_session_keys(SPK, SSK, CPK),
    %% This keypair must be shared in both directions
    conjunction([{ctx_srx, equals(CTX, SRX)}, {stx_crx, equals(STX, CRX)}])
  end).

%% SCRAMBLING
prop_scramble_block() ->
    ?FORALL({Block, Key}, {binary(16), eqc_gen:largebinary(32)},
        is_binary(enacl_ext:scramble_block_16(Block, Key))).

%% Scala multiplication
prop_scalarmult() ->
  Bytes = 32,
  ?FORALL({S1, S2, Basepoint}, {binary(Bytes), binary(Bytes), binary(Bytes)},
          equals(enacl:curve25519_scalarmult(S1,
                       enacl:curve25519_scalarmult(S2, Basepoint)),
                 enacl:curve25519_scalarmult(S2,
                       enacl:curve25519_scalarmult(S1, Basepoint)))
         ).

%% Secretstream
secretstream_key() ->
  ?LET(K, enacl:secretstream_xchacha20poly1305_keygen(), K).

secretstream_msg() ->
  ?LET({Tag, AD, Msg}, {oneof([message,rekey,push]), binary(), binary()},
    {Tag, AD, Msg}).

secretstream_msgs() ->
  ?LET({Ms, {_, AD, Msg}}, {list(secretstream_msg()), secretstream_msg()},
   Ms ++ [{final, AD, Msg}]).

push_messages(_State, []) ->
  [];
push_messages(State, [{Tag, AD, Msg}|Next]) ->
  Block = enacl:secretstream_xchacha20poly1305_push(State, Msg, AD, Tag),
  [Block|push_messages(State, Next)].

pull_messages(_State, [], []) ->
  true;
pull_messages(State, [B|Bs], [{_Tag, AD, _Msg}=Expect|Next]) ->
  {Msgx, Tagx} = enacl:secretstream_xchacha20poly1305_pull(State, B, AD),
  case equals(Expect, {Tagx, AD, Msgx}) of
    true ->
      pull_messages(State, Bs, Next);
    R ->
      R
  end.

prop_secretstream() ->
  ?FORALL({Key, Msgs}, {secretstream_key(), secretstream_msgs()},
    begin
      %% Encrypt
      {Header, State} = enacl:secretstream_xchacha20poly1305_init_push(Key),
      Blocks = push_messages(State, Msgs),
      %% Decrypt & Verify
      DState = enacl:secretstream_xchacha20poly1305_init_pull(Header, Key),
      pull_messages(DState, Blocks, Msgs)
    end).

%% HELPERS

%% INTERNAL FUNCTIONS
%% ------------------------------------------------------------

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
