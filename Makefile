.PHONY: all install uninstall clean check
PACKAGE=key-parsers
MLI=key_parsers
OBJ=$(addprefix _build/src/, $(addsuffix .cmi, $(MLI)) $(MLI).cma $(MLI).cmxa $(MLI).a)

all: $(OBJ)

_build/%:
	ocamlbuild -use-ocamlfind $*

install: uninstall
	ocamlfind install $(PACKAGE) $(OBJ) META

uninstall:
	ocamlfind remove $(PACKAGE)

clean:
	ocamlbuild -clean

check:
	ocamlbuild -use-ocamlfind -I tests test_all.byte --
