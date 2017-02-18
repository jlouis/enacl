REBAR=rebar3

.PHONY: compile
compile:
	$(REBAR) compile | sed -e 's|_build/default/lib/enacl/||g'

.PHONE: console
console: compile
	$(REBAR) shell

.PHONY: clean
clean:
	$(REBAR) clean
