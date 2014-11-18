REBAR=rebar

.PHONY: compile
compile: deps
	$(REBAR) compile

.PHONY: deps
deps:
	$(REBAR) get-deps

.PHONY: clean
clean:
	$(REBAR) clean
