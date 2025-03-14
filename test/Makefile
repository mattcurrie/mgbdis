BOLD_WHITE := \033[1;97m
RESET := \033[0m

.NOTPARALLEL:

all: clean test.gb test-disasm test-built

clean:
	@echo "$(BOLD_WHITE)Clean up...$(RESET)"
	rm -rf disassembly
	rm -rf build
	rm -f test.gb

build/test.o: clean src/test.asm
	@echo "$(BOLD_WHITE)Building test.o...$(RESET)"
	mkdir -p build
	rgbasm  -o build/test.o src/test.asm

test.gb: build/test.o
	@echo "$(BOLD_WHITE)Building test ROM...$(RESET)"
	rgblink -n build/test.sym -m build/test.map -o $@ $<
	rgbfix -v -p 255 $@
	@if which md5sum &>/dev/null; then md5sum $@; else md5 $@; fi

test-disasm:
	@echo "$(BOLD_WHITE)Generating disassembly...$(RESET)"
	rm -rf disassembly
	PYTHONWARNINGS=error ../mgbdis.py test.gb
	@diff -r --strip-trailing-cr expected disassembly \
		&& echo "✅ No differences found in disassembly!$(RESET)" \
		|| (echo "❌ Differences found between 'expected' and 'disassembly'."; exit 1)

test-built:
	@echo "$(BOLD_WHITE)Building ROM from disassembly...$(RESET)"
	$(MAKE) -C disassembly
	@bash -c 'diff -u <(xxd test.gb) <(xxd disassembly/game.gb)' \
		&& echo "✅ No differences found in assembled ROM!$(RESET)" \
		|| (echo "❌ Differences found between assembled test source and assembled disassembly."; exit 1)

update-expected:
	@echo "$(BOLD_WHITE)Updating \"expected\" from \"disassembly\"...$(RESET)"
	cp -r disassembly/* expected
