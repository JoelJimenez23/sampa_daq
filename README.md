# sampa_daq

Terminal tools to configure the **SAMPA** ASIC (MPW2 revision) and collect its
data, from the Linux running on the board (Cyclone V SoC, ARM) and from a PC.

They replace the `SAMPA communicator` GUI (C#/WinForms, Windows only) with
small pieces that can be scripted, version-controlled and run headless — over
`ssh`, which is how they are actually used in the lab.

```
   PC                                    board (socfpga_cyclone5, ARM)
   ─────────────────────                 ────────────────────────────────────
   sampa_sniff.py  <───── port 1000 ─────── sampa_server ──┐
        │  saves .bin and CSV                              │  DDR3
        │  and serves the live view                        │
        ├── sampa_view.py                  daqstat  ───────┤  FPGA registers
        └── sampa_data.py                  sampa_cfg ──────┘  I2C → SAMPA chip
```

The two board tools talk to the FPGA through `/dev/mem` + `mmap` over the
`h2f_lw` bridge at `0xFF200000`. The PC tools just open a TCP socket to
port 1000.

## The tools

| Tool | Runs on | What for | Manual |
|---|---|---|---|
| `daqstat` | board | DAQ status, enable links, start acquisitions | [docs/DAQSTAT.md](docs/DAQSTAT.md) |
| `sampa_cfg` | board | read and write SAMPA and FPGA registers, apply a TOML | [docs/CONFIG.md](docs/CONFIG.md) |
| `sampa_sniff/sampa_sniff.py` | PC | receive the data, save it and watch it live | [docs/SNIFF.md](docs/SNIFF.md) |
| `sampa_sniff/sampa_data.py` | PC | read a capture as a table, for analysis | [docs/CSV.md](docs/CSV.md) |

`sampa_view.py` is not run on its own: it builds the HTML page that
`sampa_sniff.py --web` serves, and the one generated from a saved capture.

## Layout

```
sampa_daq/
├── bin/            prebuilt ARM binaries — copy these to the board
│   ├── sampa_cfg
│   └── daqstat
├── daqstat/        source of the DAQ status tool
├── sampa_cfg/      source of the chip configuration tool
│   └── third_party/  tomlc99 (MIT), unmodified
├── sampa_sniff/    the PC tools (Python, standard library only)
│   ├── sampa_sniff.py
│   ├── sampa_view.py
│   └── sampa_data.py
├── config/         TOML configuration files
├── registers/      register CSV files and the generator that turns them into C
├── board/          startup scripts that live on the board
├── docs/           one manual per tool
└── Makefile
```

Building leaves object files in `build/` and binaries in `bin/`; `make clean`
removes `build/` and the PC binary, and leaves the two committed ARM binaries
alone.

## What you need to install

### To use the PC tools — nothing

`sampa_sniff.py`, `sampa_view.py` and `sampa_data.py` are **Python 3, standard
library only**. There is no `pip install` and no virtual environment: copy the
three files together anywhere and they work, on Linux and on Windows.

Tested with Python 3.8 and later. The live view (`--web`) needs all three in
the same directory; without `--web`, `sampa_sniff.py` works on its own.

`pandas` is optional and only for `sampa_data.py`'s `.df()` helper. Without it
the tables can still be iterated, dumped to CSV or read column by column.

### To use the board binaries — nothing

`sampa_cfg` and `daqstat` come **already compiled** in this repository. They
are statically linked, so they do not depend on the board's glibc version.
Copy and run:

```sh
scp bin/sampa_cfg bin/daqstat root@10.0.163.205:/home/root/
```

They must be run **as root**, because they use `/dev/mem`.

### To rebuild them — an ARM cross-compiler

The board is ARM and has no compiler, so you build on the PC and copy. The
quickest option is the prebuilt **Bootlin** toolchain: unpack it and you are
done, nothing is installed system-wide.

```sh
mkdir -p ~/toolchains && cd ~/toolchains
curl -O https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--glibc--stable-2024.05-1.tar.xz
tar xf armv7-eabihf--glibc--stable-2024.05-1.tar.xz
```

The `Makefile` finds it there by itself. To use a different one:

```sh
make TOOLCHAIN=/path/to/toolchain
make TOOLCHAIN= CROSS=arm-linux-gnueabihf-    # one installed system-wide
```

> **Do not use the Linaro links.** Linaro shut down its binary server: today
> `releases.linaro.org/components/toolchain/binaries/...` returns **200 OK**
> with 58 kB of HTML. `curl -O` saves that page under the `.tar.xz` name
> without complaining, and you end up with a "toolchain" that is a web page.

Compatibility details for the board's Linux 3.15 are in [docs/CONFIG.md](docs/CONFIG.md).

### Third-party libraries — one, and it is already included

**[tomlc99](https://github.com/cktan/tomlc99)** by CK Tan, MIT licence: the
files `toml.c` and `toml.h`, which `sampa_cfg apply` uses. They are in the
repository **unmodified**, identical to upstream, so it builds with nothing to
download. If they ever need updating:

```sh
curl -O https://raw.githubusercontent.com/cktan/tomlc99/master/toml.c
curl -O https://raw.githubusercontent.com/cktan/tomlc99/master/toml.h
```

There is no other dependency, in C or in Python.

## Building

```sh
make               # bin/sampa_cfg  ARM, for the board
make daqstat       # bin/daqstat    ARM, for the board
make native        # bin/sampa_cfg_pc   x86, only to validate TOML with --dry-run
make check         # check that the hardware layer compiles, build nothing
make check-all     # check that everything compiles, build nothing
make regs          # regenerate the register tables from registers/*.csv
make clean
```

Always check you got an ARM binary and not a PC one:

```
$ file bin/sampa_cfg
bin/sampa_cfg: ELF 32-bit LSB executable, ARM, EABI5 version 1 (GNU/Linux),
statically linked, for GNU/Linux 3.2.0
```

## Getting started

With the board up and the chip powered, in two terminals:

```sh
# 1. PC: the receiver first. With no client connected the FPGA pushes nothing.
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 -q --web --board --save run1.bin
```

```sh
# 2. board
./daqstat                  # STATUS_REG must read 0x0000000F
./daqstat links auto
./daqstat acquire 2048
```

And afterwards, without going back to the board:

```sh
python3 sampa_sniff/sampa_sniff.py -f run1.bin --csv run1 --csv-long -q
```

> If `STATUS_REG` does not read `0x0000000F`, **power-cycle the board** before
> touching anything else. It is established that this is not a configuration
> problem: see [docs/DAQSTAT.md](docs/DAQSTAT.md), troubleshooting section.

## Where the register tables come from

Register names, addresses and widths are **not hand-written** in the C code:
they are generated.

```
registers/globreg.csv    SAMPA global registers   ─┐
registers/chreg.csv      SAMPA channel registers   ├─ gen_regs.py ─→ sampa_cfg/sampa_regs.c
registers/fpga_regs.csv  FPGA fields (CNC and DM) ─┘                 sampa_cfg/fpga_regs.c
```

The first two are a copy of `Resources/` from the Windows GUI, which is the
project's source of truth. **To add or change a register you edit the CSV and
run `make regs`**, never the generated `.c`.

## The files

| File | What it is |
|---|---|
| `sampa_cfg/main.c` | `sampa_cfg`'s command line |
| `sampa_cfg/sampa_hw.c/.h` | bridge to the FPGA, I2C and SAMPA registers |
| `sampa_cfg/config.c/.h` | reads the TOML and applies it in the right order |
| `daqstat/daqstat.c` | the DAQ status tool |
| `sampa_cfg/sampa_regs.c/.h`, `fpga_regs.c/.h` | register tables — **generated**, do not edit |
| `registers/gen_regs.py` | generates them from the CSV files |
| `registers/*.csv` | the register CSV files |
| `sampa_sniff/sampa_sniff.py` | receiver: saves, decodes and serves the live view |
| `sampa_sniff/sampa_view.py` | builds the HTML page |
| `sampa_sniff/sampa_data.py` | reads a `.bin` as a table, for analysis |
| `config/bench.toml` | **this bench's configuration**, verified against the chip |
| `config/example.toml` | example of the TOML format. Not this bench's configuration |
| `config/minimal_test.toml` | harmless test of `apply` against hardware |
| `board/daq_init.sh`, `sampa_server.init` | automatic startup on the board |
| `sampa_cfg/third_party/toml.*` | tomlc99, third-party, unmodified |

## Warnings that were learned the hard way

- **Use `bench.toml`, not `example.toml`.** The second one enables all eleven
  serial links, resets the SAMPA and configures a second chip that does not
  exist on this board.
- **Do not run `sampa_cfg fixsync`**: to run its sweep it rewrites `SOCFG` and
  the `CHEN` registers, and does not put them back.
- If the links do not lock or no packets arrive, **power-cycle the board**.
  Rebooting Linux is not enough. This was established by dumping every FPGA
  and chip register in a broken boot and in a good one: they are identical, so
  there is nothing to reconfigure.
- The chip on this bench has **channels 10 and 23 dead**. That is silicon of
  an MPW2 prototype, not configuration.
- The `[pll]` block of `bench.toml` is disabled on purpose, with the real
  measured dividers written inside it. Read them before enabling it: values
  that look plausible but are wrong leave the clocks at half speed and bring
  the serial links down.
- **Huffman compression cannot be decoded**: section 1.5.1 of the SAMPA
  specification, which should carry the code table, is empty.
  `sampa_sniff.py` flags those packets instead of inventing samples.

## Language

Everything here — code, comments, identifiers and documentation — is in
English so the project can be picked up anywhere. A Spanish-language copy of
the tree, from which this one was translated, is kept alongside as
`sampa_daq_espanol`.
