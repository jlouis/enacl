REBAR=rebar3
RUN_EQC=erl -pa _build/default/lib/enacl/ebin -noshell -s enacl_eqc -s init stop

.PHONY: compile
compile:
	$(REBAR) compile

.PHONY: tests
tests:
	$(REBAR) ct

eqc_compile: compile
	erlc -o _build/default/lib/enacl/ebin eqc_test/enacl_eqc.erl

eqc_mini_compile: compile
	erlc -Dmini -o _build/default/lib/enacl/ebin eqc_test/enacl_eqc.erl

eqc_run: eqc_compile
	$(RUN_EQC)

eqc_mini_run: eqc_mini_compile
	$(RUN_EQC)

.PHONE: console
console: compile
	$(REBAR) shell

.PHONY: clean
clean:
	$(REBAR) clean
