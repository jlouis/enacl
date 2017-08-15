REBAR=rebar3

.PHONY: compile
compile:
	$(REBAR) compile | sed -e 's|_build/default/lib/enacl/||g'

eqc_compile: compile
	erlc -o _build/default/lib/enacl/ebin eqc_test/enacl_eqc.erl

.PHONE: console
console: compile
	$(REBAR) shell

.PHONY: clean
clean:
	$(REBAR) clean
