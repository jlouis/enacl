-module(enacl_SUITE).
-include_lib("common_test/include/ct.hrl").

-compile([export_all, nowarn_export_all]).

suite() ->
    [{timetrap, {seconds, 30}}].

init_per_group(_Group, Config) ->
    Config.

end_per_group(_Group, _Config) ->
    ok.

init_per_suite(Config) ->
    application:ensure_all_started(enacl),
    Config.

end_per_suite(_Config) ->
    application:stop(enacl),
    ok.

init_per_testcase(x, Config) ->
    {ok, _} = dbg:tracer(),
    dbg:p(all, c),
    dbg:tpl(graphql_execute, lookup_field, '_', cx),
    Config;
init_per_testcase(_Case, Config) ->
    Config.

end_per_testcase(x, _Config) ->
    dbg:stop_clear(),
    ok;
end_per_testcase(_Case, _Config) ->
    ok.

groups() ->
    Neg = {negative, [shuffle, parallel],
      [generichash_basic_neg]},
    Pos = {positive, [shuffle, parallel],
                    [
                     aead_chacha20poly1305_ietf,
                     aead_xchacha20poly1305,
                     generichash_basic_pos,
                     generichash_chunked,
                     kx,
                     pwhash,
                     secretstream,
                     sign,
                     verify_detached
                    ]},

    [Neg, Pos].

all() ->
    [{group, negative},
     {group, positive}].

%% -- BASIC --------------------------------------
generichash_basic_neg(_Config) ->
    %% Negative generichash invocations
    Msg = <<"I've seen things you people wouldn't believe: attack ships on fire off the shoulder of Orion. "
            "I've watched C-beams glitter in the dark near the Tannhäuser Gate. "
            "All those... moments... will be lost... in time, like... tears... in rain">>,
    Key = <<"Hash Key 123456789">>,
    {'EXIT', {badarg, _}} = (catch enacl:generichash(9, Msg, Key)),
    {'EXIT', {badarg, _}} = (catch enacl:generichash(65, Msg, Key)),
    {'EXIT', {badarg, _}} = (catch enacl:generichash(32, Msg, <<"Small">>)),
    ok.

generichash_basic_pos(_Config) ->
    Msg = <<"I've seen things you people wouldn't believe: attack ships on fire off the shoulder of Orion. "
            "I've watched C-beams glitter in the dark near the Tannhäuser Gate. "
            "All those... moments... will be lost... in time, like... tears... in rain">>,
    Key = <<"Hash Key 123456789">>,
    <<189,104,45,187,170,229,212,4,121,43,137,74,241,173,181,77,
          67,211,133,70,196,6,128,97>> = enacl:generichash(24, Msg, Key),
    ok.

generichash_chunked(_Config) ->
    Msg = <<"I've seen things you people wouldn't believe: attack ships on fire off the shoulder of Orion. "
            "I've watched C-beams glitter in the dark near the Tannhäuser Gate. "
            "All those... moments... will be lost... in time, like... tears... in rain">>,
    Key = <<"Hash Key 123456789">>,
    State = enacl:generichash_init(24, Key),
    State = generichash_chunked(State, Msg, 10000),
    Expected = <<46,49,32,18,13,186,182,105,106,122,253,139,89,176,169,141,
                 73,93,99,6,41,216,110,41>>,
    Expected = enacl:generichash_final(State),
    try enacl:generichash_final(State) of
        _ -> ct:fail(must_finalize)
    catch
        error:enacl_finalized ->
            ok
    end,
    try enacl:generichash_update(State, <<"x">>) of
        _ -> ct:fail(must_finalize)
    catch
        error:enacl_finalized ->
            ok
    end,
    ok.

generichash_chunked(State, _Msg, 0) -> State;
generichash_chunked(State, Msg, N) ->
    State2 = enacl:generichash_update(State, Msg),
    generichash_chunked(State2, Msg, N-1).

aead_xchacha20poly1305(_Config) ->
    NonceLen = enacl:aead_xchacha20poly1305_ietf_NPUBBYTES(),
    KLen = enacl:aead_xchacha20poly1305_ietf_KEYBYTES(),
    Key = binary:copy(<<"K">>, KLen),
    Msg = <<"test">>,
    AD = <<1,2,3,4,5,6>>,
    Nonce = binary:copy(<<"N">>, NonceLen),

    CipherText = enacl:aead_xchacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key),
    Msg = enacl:aead_xchacha20poly1305_ietf_decrypt(CipherText, AD, Nonce, Key),
    ok.

aead_chacha20poly1305_ietf(_Config) ->
    NonceLen = enacl:aead_chacha20poly1305_ietf_NPUBBYTES(),
    KLen = enacl:aead_chacha20poly1305_ietf_KEYBYTES(),
    Key = binary:copy(<<"K">>, KLen),
    Msg = <<"test">>,
    AD = <<1,2,3,4,5,6>>,
    Nonce = binary:copy(<<"N">>, NonceLen),

    CipherText = enacl:aead_chacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key),
    Msg = enacl:aead_chacha20poly1305_ietf_decrypt(CipherText, AD, Nonce, Key),
    ok.

pwhash(_Config) ->
    PW = <<"XYZZY">>,
    Salt = <<"1234567890abcdef">>,
    Hash1 = <<164,75,127,151,168,101,55,77,48,77,240,204,64,20,43,23,88,
                 18,133,11,53,151,2,113,232,95,84,165,50,7,60,20>>,
    Hash1 = enacl:pwhash(PW, Salt),
    Str1 = enacl:pwhash_str(PW),
    true = enacl:pwhash_str_verify(Str1, PW),
    false = enacl:pwhash_str_verify(Str1, <<PW/binary, 1>>),
    16 = enacl:pwhash_SALTBYTES(),
    ok.

sign(_Config) ->
    #{public := PK, secret := SK} = enacl:sign_keypair(),
    Msg = <<"Test">>,
    State = enacl:sign_init(),
    Create = sign_chunked(State, Msg, 10000),
    {ok, Signature} = enacl:sign_final_create(Create, SK),
    StateVerify = enacl:sign_init(),
    Verify = sign_chunked(StateVerify, Msg, 10000),
    true = enacl:sign_final_verify(Verify, Signature, PK),
    ok.

sign_chunked(S, _M, 0) -> S;
sign_chunked(S, M, N) ->
    S2 = enacl:sign_update(S, M),
    sign_chunked(S2, M, N-1).

kx(_Config) ->
    #{ public := CPK, secret := CSK} = enacl:kx_keypair(),
    #{ public := SPK, secret := SSK} = enacl:kx_keypair(),
    #{ client_tx := CTX, client_rx := CRX} = enacl:kx_client_session_keys(CPK, CSK, SPK),
    #{ server_tx := STX, server_rx := SRX} = enacl:kx_server_session_keys(SPK, SSK, CPK),
    %% Verify we got a shared keypair
    CTX = SRX,
    STX = CRX,
    ok.

secretstream(_Config) ->
    Part1 = <<"Arbitrary data to encrypt">>,
    Part2 = <<"split into">>,
    Part3 = <<"three messages">>,

    Key = enacl:secretstream_xchacha20poly1305_keygen(),

    %% Encrypt
    {Header, State} = enacl:secretstream_xchacha20poly1305_init_push(Key),
    Block1 = enacl:secretstream_xchacha20poly1305_push(State, Part1, <<"AD1">>, message),
    Block2 = enacl:secretstream_xchacha20poly1305_push(State, Part2, <<>>, message),
    Block3 = enacl:secretstream_xchacha20poly1305_push(State, Part3, <<"AD3">>, final),

    %% Decrypt
    DState = enacl:secretstream_xchacha20poly1305_init_pull(Header, Key),
    {Part1, message} = enacl:secretstream_xchacha20poly1305_pull(DState, Block1, <<"AD1">>),
    {Part2, message} = enacl:secretstream_xchacha20poly1305_pull(DState, Block2, <<>>),
    {Part3, final} = enacl:secretstream_xchacha20poly1305_pull(DState, Block3, <<"AD3">>),
    ok.

verify_detached(_Config) ->
    #{ public := PK, secret := SK} = enacl:sign_keypair(),
    M = <<"Arbitrary data to encrypt">>,
    Sig = enacl:sign_detached(M, SK),
    true = enacl:sign_verify_detached(Sig, M, PK),
    ok.
