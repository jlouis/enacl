REBAR=rebar3

.PHONY: compile
compile:
	$(REBAR) compile | sed -e 's|_build/default/lib/enacl/||g'

.PHONY: clean
clean:
	$(REBAR) clean
