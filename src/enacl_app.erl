-module(enacl_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
	enacl_sup:start_link().

stop(_State) ->
	ok.
