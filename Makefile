REBAR=rebar3

.PHONY: compile
compile:
	$(REBAR) compile

.PHONY: clean
clean:
	$(REBAR) clean
