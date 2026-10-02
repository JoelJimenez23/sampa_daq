# Makefile for sampa_cfg and daqstat
#
# Same CPU flags as sampa_server (Cortex-A9 of the Cyclone V).

# TOOLCHAIN: directory of the unpacked cross-compiler. If you set it, its
# bin/ is prepended to PATH and nothing has to be installed system-wide.
# The Bootlin toolchain (armv7-eabihf, glibc) is downloaded from
#   https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/
# NOTE: the Linaro link that circulates online has been DEAD since 2023: it
# now redirects to linaro.org/contact and the .tar.xz you get is 58 kB of
# HTML.
TOOLCHAIN  ?= $(HOME)/toolchains/armv7-eabihf--glibc--stable-2024.05-1
ifneq ($(wildcard $(TOOLCHAIN)/bin),)
  export PATH := $(TOOLCHAIN)/bin:$(PATH)
  # Bootlin's is produced by buildroot and uses its own prefix
  ifneq ($(wildcard $(TOOLCHAIN)/bin/arm-buildroot-linux-gnueabihf-gcc),)
    CROSS ?= arm-buildroot-linux-gnueabihf-
  endif
endif

CROSS      ?= arm-linux-gnueabihf-
CC          = $(CROSS)gcc
CPU_CFLAGS  = -march=armv7-a -mthumb -mfpu=neon -mfloat-abi=hard -mtune=cortex-a9
CFLAGS      = -Wall -Wextra -O2 $(CPU_CFLAGS)

# Static linking by default. The binary goes from ~30 kB to ~700 kB, but it
# stops depending on whichever glibc the board has, which is the usual way a
# cross-compiled binary fails to start ("version `GLIBC_2.34' not found").
# With STATIC=0 it is linked dynamically.
STATIC     ?= 1
ifeq ($(STATIC),1)
  LDFLAGS  += -static
endif

# --- Where things live -----------------------------------------------------
CFG_DIR     = sampa_cfg
TP_DIR      = $(CFG_DIR)/third_party
DAQ_DIR     = daqstat
REG_DIR     = registers
BIN_DIR     = bin
BUILD_DIR   = build

CFLAGS     += -I$(CFG_DIR) -I$(TP_DIR)

CFG_SRC     = $(CFG_DIR)/main.c $(CFG_DIR)/sampa_hw.c $(CFG_DIR)/sampa_regs.c \
              $(CFG_DIR)/fpga_regs.c $(CFG_DIR)/config.c
OBJS        = $(patsubst $(CFG_DIR)/%.c,$(BUILD_DIR)/%.o,$(CFG_SRC)) \
              $(BUILD_DIR)/toml.o

# The register CSV files are the source of truth and live in registers/,
# copied from Resources/ of the "SAMPA communicator" GUI. They are kept in
# the repository so this builds without needing that other project alongside.
RESOURCES  ?= $(REG_DIR)

# The default goal must build both board binaries. Without this, the first
# rule in the file wins, which used to be the directory below: plain "make"
# created build/ and reported success without compiling a thing.
.DEFAULT_GOAL := all

all: sampa_cfg daqstat

$(BUILD_DIR) $(BIN_DIR):
	@mkdir -p $@

# --- Binary for the BOARD (ARM) -------------------------------------------
sampa_cfg: $(TP_DIR)/toml.h cross-check | $(BIN_DIR)
	@$(MAKE) --no-print-directory $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BIN_DIR)/$@ $(OBJS)
	@echo ""
	@echo "  Done: bin/sampa_cfg  (ARM binary, for the board)"
	@echo ""
	@file $(BIN_DIR)/$@ 2>/dev/null || true
	@echo ""
	@echo "  Copy it with:  scp bin/sampa_cfg root@<board-ip>:/home/root/"
	@echo ""

# --- Diagnostic tool (ARM, for the board) ---------------------------------
# Reads the DAQ registers in the FPGA. Needed because the board's BusyBox
# does not ship the devmem applet.
daqstat: $(DAQ_DIR)/daqstat.c cross-check | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(BIN_DIR)/$@ $<
	@file $(BIN_DIR)/$@

$(BUILD_DIR)/%.o: $(CFG_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# toml.c is third-party: compiled without -Wextra to avoid a wall of warnings.
$(BUILD_DIR)/toml.o: $(TP_DIR)/toml.c | $(BUILD_DIR)
	$(CC) -Wall -O2 $(CPU_CFLAGS) -c -o $@ $<

cross-check:
	@which $(CC) > /dev/null 2>&1 || ( \
	  echo ""; \
	  echo "  Cannot find the cross-compiler '$(CC)'."; \
	  echo "  (looked in $(TOOLCHAIN)/bin and in PATH)"; \
	  echo ""; \
	  echo "  Without it the ARM binary for the board cannot be built."; \
	  echo "  The quickest way is a prebuilt toolchain, nothing to install:"; \
	  echo ""; \
	  echo "      mkdir -p ~/toolchains && cd ~/toolchains"; \
	  echo "      curl -O https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--glibc--stable-2024.05-1.tar.xz"; \
	  echo "      tar xf armv7-eabihf--glibc--stable-2024.05-1.tar.xz"; \
	  echo ""; \
	  echo "  (or, building it yourself, from the AUR: paru -S arm-linux-gnueabihf-gcc)"; \
	  echo ""; \
	  echo "  Meanwhile, to test the TOML on the PC with no board:"; \
	  echo ""; \
	  echo "      make native && ./sampa_cfg_pc --dry-run apply ejemplo.toml"; \
	  echo ""; \
	  false )

# tomlc99 no viene incluido (licencia MIT, dos ficheros). Si falta, avisa
# with instructions instead of an unreadable compiler error.
toml.h:
	@echo ""
	@echo "  tomlc99 is missing. Download both files into this directory:"
	@echo ""
	@echo "    curl -O https://raw.githubusercontent.com/cktan/tomlc99/master/toml.c"
	@echo "    curl -O https://raw.githubusercontent.com/cktan/tomlc99/master/toml.h"
	@echo ""
	@echo "  (o: git clone https://github.com/cktan/tomlc99 && cp tomlc99/toml.[ch] .)"
	@echo ""
	@false

# Check with the PC's gcc that the hardware layer compiles.
# Not usable on the board (that binary has to be ARM).
check:
	gcc -Wall -Wextra -O2 -I$(CFG_DIR) -c -o /dev/null $(CFG_DIR)/sampa_hw.c
	gcc -Wall -Wextra -O2 -I$(CFG_DIR) -c -o /dev/null $(CFG_DIR)/sampa_regs.c
	gcc -Wall -Wextra -O2 -I$(CFG_DIR) -c -o /dev/null $(CFG_DIR)/fpga_regs.c
	@echo "the hardware layer compiles with no errors"

# Same as 'check' but including the TOML reader (needs tomlc99).
# NOTE: this only CHECKS that it compiles. It does not build ./sampa_cfg.
check-all: $(TP_DIR)/toml.h
	gcc -Wall -Wextra -O2 -I$(CFG_DIR) -I$(TP_DIR) -c -o /dev/null $(CFG_DIR)/main.c
	gcc -Wall -Wextra -O2 -I$(CFG_DIR) -I$(TP_DIR) -c -o /dev/null $(CFG_DIR)/config.c
	gcc -Wall -Wextra -O2 -c -o /dev/null $(DAQ_DIR)/daqstat.c
	@echo "everything compiles with no errors (this builds no binary)"

# --- Binary for the PC -----------------------------------------------------
# Used to validate the TOML file with --dry-run, no board needed.
# It CANNOT talk to the hardware: that needs 'make'.
native: $(TP_DIR)/toml.h | $(BIN_DIR)
	@mkdir -p $(BUILD_DIR)
	gcc -Wall -O2 -I$(TP_DIR) -c -o $(BUILD_DIR)/toml_pc.o $(TP_DIR)/toml.c
	gcc -Wall -Wextra -O2 -I$(CFG_DIR) -I$(TP_DIR) -o $(BIN_DIR)/sampa_cfg_pc \
	    $(CFG_SRC) $(BUILD_DIR)/toml_pc.o
	@echo ""
	@echo "  Done: bin/sampa_cfg_pc  (PC binary, only for --dry-run)"
	@echo ""
	@echo "      ./bin/sampa_cfg_pc --dry-run apply config/bench.toml"
	@echo ""

# Regenerate the register tables from the CSV files
regs:
	python3 $(REG_DIR)/gen_regs.py "$(RESOURCES)" "$(CFG_DIR)"

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)/sampa_cfg_pc

.PHONY: all check check-all native cross-check regs clean
