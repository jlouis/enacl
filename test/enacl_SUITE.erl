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
    GenericHashNeg = {generichash_neg, [shuffle, parallel],
      [generichash_basic_neg]},
    GenericHash = {generichash, [shuffle, parallel, {repeat, 100}],
                    [generichash_basic_pos,
                     generichash_chunked]},

    [GenericHashNeg, GenericHash].

all() ->
    [{group, generichash}].

%% -- BASIC --------------------------------------
generichash_basic_neg(_Config) ->
    %% Negative generichash invocations
    Msg = <<"I've seen things you people wouldn't believe: attack ships on fire off the shoulder of Orion. "
            "I've watched C-beams glitter in the dark near the Tannhäuser Gate. "
            "All those... moments... will be lost... in time, like... tears... in rain">>,
    Key = <<"Hash Key 123456789">>,
    {error, invalid_hash_size} = enacl:generichash(9, Msg, Key),
    {error, invalid_hash_size} = enacl:generichash(65, Msg, Key),
    {error, invalid_key_size} = enacl:generichash(32, Msg, <<"Small">>),
    ok.

generichash_basic_pos(_Config) ->
    Msg = <<"I've seen things you people wouldn't believe: attack ships on fire off the shoulder of Orion. "
            "I've watched C-beams glitter in the dark near the Tannhäuser Gate. "
            "All those... moments... will be lost... in time, like... tears... in rain">>,
    Key = <<"Hash Key 123456789">>,
    {ok,<<189,104,45,187,170,229,212,4,121,43,137,74,241,173,181,77,
          67,211,133,70,196,6,128,97>>} = enacl:generichash(24, Msg, Key),
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
    {ok, Expected} = enacl:generichash_final(State),
    ok.

generichash_chunked(State, _Msg, 0) -> State;
generichash_chunked(State, Msg, N) ->
    State2 = enacl:generichash_update(State, Msg),
    generichash_chunked(State2, Msg, N-1).

