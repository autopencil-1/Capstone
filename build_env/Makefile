# ==== config ====
CL      ?= clang 
CFLAGS  ?= -w -O0 -fno-split-machine-functions \
           -fbasic-block-sections=all -funique-basic-block-section-names
LDFLAGS ?= -fuse-ld=lld -Wl,--icf=none -Wl,--no-gc-sections
SEED    ?= 12345
SHUFFLE ?= .text.*
MERGE   ?= 1
STRIP	?= 1

SRC := main.obf.c opaque/opaque.c
OBJ := $(SRC:.c=.o)
BIN := main

SHUFFLE_FLAG := -Wl,"--shuffle-sections=$(SHUFFLE)=$(SEED)"

.PHONY: all clean

all: $(BIN)
ifeq ($(STRIP),1)
	@if command -v llvm-strip >/dev/null 2>&1; then \
		llvm-strip -s $(BIN); \
	else \
		strip -s $(BIN); \
	fi
	@echo "stripped: $(BIN)"
endif

%.o: %.c
	$(CL) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJ)
	$(CL) $(OBJ) -o $@ $(LDFLAGS) $(SHUFFLE_FLAG)
ifeq ($(MERGE),1)
	@echo "[merge] rename .text.* -> .text"
	@for sec in `readelf -W -S $@ | awk '/\.text\.[^ ]+/ {print $$2}'`; do \
		objcopy --rename-section $$sec=.text $@ ; \
	done
endif

clean:
	@rm -f $(OBJ) $(BIN) merge_text.ld link.map

merge_text.ld:
	@{ \
	  printf 'SECTIONS\n'; \
	  printf '{\n'; \
	  printf '  .text :\n'; \
	  printf '  {\n'; \
	  printf '    *(.text)\n'; \
	  printf '    *(.text.*)\n'; \
	  printf '  }\n'; \
	  printf '}\n'; \
	} > $@
	@echo "generated: $@"
