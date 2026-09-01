# sampa_cfg — manual

Configures the SAMPA chip from the Linux running on the board's HPS, without
going through the PC's GUI or the serial port.

```
sampa_cfg (Linux/ARM)
    |  /dev/mem + mmap at 0xFF200000
    v
h2f_lw bridge  (inside the Cyclone V)
    |  offset 0x3000
    v
i2c_master block (FPGA logic)
    |  I2C bus, 960 kHz
    v
SAMPA chip
```

`0xFF200000` **is not DDR3 memory**: these are registers inside the FPGA. The
DDR3 (`0x30000000`) is used only by `sampa_server`, for event data.

The Windows GUI reaches the *same* `i2c_master`, but over the UART. Both paths
are wired to the same block in `hps.qsys`; only the transport differs.

---

## Reference

```
sampa_cfg [OPTIONS] probe    [chip]
sampa_cfg [OPTIONS] dump     [chip]
sampa_cfg [OPTIONS] dumpch   <chip> <channel>
sampa_cfg [OPTIONS] read     <chip> <NAME>
sampa_cfg [OPTIONS] write    <chip> <NAME> <value>
sampa_cfg [OPTIONS] readch   <chip> <channel> <NAME>
sampa_cfg [OPTIONS] writech  <chip> <channel|all> <NAME> <value>
sampa_cfg [OPTIONS] apply    <file.toml>
sampa_cfg            regs
sampa_cfg [OPTIONS] fixsync  [ms]
```

It runs **on the board and needs root**, because it uses `/dev/mem`. `chip` is
the SAMPA's hardware address (0 if there is only one) and defaults to 0.
Values may be decimal or hexadecimal (`0x..`).

### Commands

| Command | What it does | Needs the board |
|---|---|---|
| `probe` | reads `HWADD` and checks that the I2C path works | yes |
| `dump` | dumps all 40 global registers with their descriptions | yes |
| `dumpch` | dumps the 31 registers of one channel | yes |
| `read` | reads a global register by name | yes |
| `write` | writes a global register by name | yes |
| `readch` | reads a channel register | yes |
| `writech` | writes a channel register; `all` broadcasts to all 32 | yes |
| `apply` | applies a whole TOML configuration file | yes (unless `--dry-run`) |
| `regs` | lists the valid register names | **no** |
| `fixsync` | trains the serial links by sweeping edge and delay | yes |

`probe` is the first thing to try: if it returns the right `HWADD`, the whole
path is good and you can build on it.

> **Do not run `fixsync` on this bench.** To run its sweep it rewrites `SOCFG`
> to 0x1B (eleven serial outputs) and the `CHEN` registers to 0xFF, and does
> not restore them. It has destabilised links that were working.

### Options

| Option | What it does |
|---|---|
| `-v` | trace every I2C transaction on `stderr` |
| `--verify` | after writing each global register, read it back and compare. `apply` only |
| `--dry-run` | show what it would do, touching no hardware. `apply` only |

### Exit status

| Code | Meaning |
|---|---|
| `0` | all good |
| `1` | hardware failure: no I2C response, read-only register, or errors during `apply` |
| `2` | usage error: unknown command or missing arguments |

### Hardware error messages

| Message | What to check |
|---|---|
| `could not open /dev/mem (root required)` | run it as root |
| `mmap of the h2f_lw bridge failed` | the lwhps2fpga bridge is disabled |
| `the i2c_master did not respond` | FPGA not programmed? clock stopped? |
| `the SAMPA did not answer` | wrong chip address? no clock? no power? |
| `arbitration lost on the I2C bus` | another master on the bus |
| `chip/channel/register out of range` | invalid argument |

> I2C write responses are **not always checked**. A `write` printing the value
> does not prove it reached the chip; to be sure, read it back with `read`, or
> use `apply --verify`.

### Configuration files

| File | What for |
|---|---|
| `bench.toml` | **this bench's configuration**, verified register by register against the chip |
| `example.toml` | example of the format. Enables all 11 links, resets the SAMPA and configures a chip 1 that does not exist here |
| `minimal_test.toml` | harmless test of `apply` against hardware: one register, no resets |

---

## Building

The PC is x86 and the board is ARM, so the binary must be **cross-compiled**.
You need a cross-compiler; **tomlc99** (two files, MIT licence) is already in
the tree: `toml.c` and `toml.h`, identical to upstream and unmodified.

### The cross-compiler

The quickest option is the prebuilt **Bootlin** toolchain: unpack it and you
are done, nothing installed system-wide.

```sh
mkdir -p ~/toolchains && cd ~/toolchains
curl -O https://toolchains.bootlin.com/downloads/releases/toolchains/armv7-eabihf/tarballs/armv7-eabihf--glibc--stable-2024.05-1.tar.xz
tar xf armv7-eabihf--glibc--stable-2024.05-1.tar.xz
```

The Makefile looks there by itself (`TOOLCHAIN` variable) and detects its
prefix (`arm-buildroot-linux-gnueabihf-`). To use a different one:

```sh
make TOOLCHAIN=/path/to/toolchain
make TOOLCHAIN= CROSS=arm-linux-gnueabihf-    # one installed system-wide
```

On Arch/CachyOS it is also in the AUR (`paru -S arm-linux-gnueabihf-gcc`), but
that is a bootstrap of four chained packages and takes a while.

> **Do not use the Linaro links.** Linaro shut down its binary server: today
> `releases.linaro.org/components/toolchain/binaries/...` redirects to their
> contact form and returns **200 OK** with 58 kB of HTML. `curl -O` and `wget`
> save that page under the `.tar.xz` name without a word of warning, and you
> end up with a "toolchain" that is in fact a web page.

### Board compatibility

The board (`socfpga_cyclone5`) runs **Linux 3.15** with a BusyBox userland.
Two things make the binary start there:

- The Makefile links **statically** by default (`STATIC=1`). That way it does
  not depend on the board's glibc version, which is the usual cause of
  `version 'GLIBC_2.34' not found`. With `STATIC=0` it links dynamically.
- Bootlin's glibc is built with `--enable-kernel=3.2`, i.e. it requires kernel
  >= 3.2.0 and the board has 3.15. Check with `readelf -n sampa_cfg` (the
  `OS: Linux, ABI: 3.2.0` line). If some day the toolchain required more than
  the board's kernel, the binary would abort with *"FATAL: kernel too old"*;
  the way out then is Bootlin's **musl** toolchain, which has no such check.

### Targets

```sh
make                    # builds bin/sampa_cfg     <- ARM binary, for the BOARD
make native             # builds bin/sampa_cfg_pc  <- PC binary, --dry-run only
make check              # only checks that the hardware layer compiles
make check-all          # only checks that everything compiles (builds NOTHING)
make clean
```

Mind the difference:

| Command | Builds | What for |
|---|---|---|
| `make` | `bin/sampa_cfg` | the ARM binary you copy to the board |
| `make native` | `bin/sampa_cfg_pc` | validating the TOML on the PC, with no board |
| `make check`, `check-all` | **nothing** | they only see whether it compiles |

If the cross-compiler is missing, `make` says so and explains what to do
instead of emitting an unreadable compiler error.

To confirm you got an ARM binary and not a PC one:

```
$ file bin/sampa_cfg
bin/sampa_cfg: ELF 32-bit LSB executable, ARM, EABI5 version 1 (GNU/Linux),
statically linked, for GNU/Linux 3.2.0
```

---

## Using it

Copy it to the board (SD card, scp...) and run it **as root**, because it uses
`/dev/mem`:

```sh
# 1. Check the path works: read HWADD of chip 0
./sampa_cfg probe 0

# 2. See every global register
./sampa_cfg dump 0

# 3. Read / write one by name
./sampa_cfg read  0 VACFG
./sampa_cfg write 0 VACFG 0x31

# 4. Channel registers
./sampa_cfg readch  0 5 ZSTHR
./sampa_cfg writech 0 all ZSTHR 400     # 'all' = all 32 channels

# 5. List the valid names (no board needed)
./sampa_cfg regs

# 6. Apply a complete configuration file
./sampa_cfg apply config/bench.toml
./sampa_cfg --verify apply config/bench.toml   # read back to check
./sampa_cfg --dry-run apply config/bench.toml  # only show, touch nothing

# -v before the command traces every I2C transaction
./sampa_cfg -v probe 0
```

---

## Files

| File | What it is |
|---|---|
| `sampa_hw.c/.h` | bridge + I2C + SAMPA registers |
| `sampa_regs.c` | name table — **generated**, do not edit |
| `sampa_regs.h` | the type and the lookup functions |
| `gen_regs.py` | generates `sampa_regs.c` and `fpga_regs.c` from the CSV files |
| `fpga_regs.csv` | FPGA fields (CNC and DM), extracted from Form1.cs |
| `resources/globreg.csv` | SAMPA global registers — source of truth |
| `resources/chreg.csv` | SAMPA channel registers — source of truth |
| `fpga_regs.c/.h` | FPGA table — **generated**, do not edit |
| `config.c/.h` | reads the TOML and applies it in the right order |
| `main.c` | the command-line tool |
| `example.toml` | example configuration file |

The register table comes from the CSV files in `resources/`, copied from
`Resources/` of the Windows GUI. They are the source of truth. If they change:

```sh
make regs
```

---

## What the configuration file covers

The same ground as the GUI, minus what is not configuration:

| Covered | Where |
|---|---|
| Clocks (PLL: M, N and dividers) | `[pll]` |
| FPGA registers (CNC and DM), by field | `[fpga.cnc]`, `[fpga.dm]` |
| ...and by raw 32-bit value | `[fpga.cnc.raw]`, `[fpga.dm.raw]` |
| SAMPA global registers | `[chip.global]` |
| Channel registers, with broadcast | `[chip.channels.all]`, `[chip.channels.N]` |
| Several chips | several `[[chip]]` blocks |
| Resets and synchronisation | `[sequence]` |

### Raw writes to the FPGA

`fpga_regs.csv` names 18 fields, but not every bit. Of `SMP_CFG_REG`, for
instance, it only names three. For the rest there are `[fpga.cnc.raw]` and
`[fpga.dm.raw]`, which write a whole 32-bit word by register number — the same
thing as the hex box on the GUI's "FPGA registers" page:

```toml
[fpga.cnc]
slvs_enable = 1        # named field

  [fpga.cnc.raw]
  12 = 0x13000037      # the whole SMP_CFG_REG
  "0x04" = 0           # the number may also be hex, in quotes
```

The raw writes are applied **before** the named fields of the same block, so
you can set the whole register and then tune one field on top of it (named
fields are read-modify-write). The other way round would not work: the raw
write would wipe out the fine tuning.

It only accepts registers the GUI allows writing (`cnc_reg_RO[]` and
`dm_reg_RO[]` in `Form1.cs`); point it at a read-only counter and it says so
and writes nothing.

**Not** included, on purpose, because these are actions or monitoring rather
than configuration: the Status tab (counters), the hardware tests (JTAG,
memory, ring oscillator, baseline), the TCP acquisition and the debug tab.

---

## Still open

- Pedestal memory (1024 values per channel). Deliberately left out of this
  first version. It is 1024 numbers per channel, which do not fit the
  `REGISTER = value` shape of the rest of the file; the natural design would
  be a separate CSV referenced from the TOML.
- `apply` has been tested **against the board**: it writes over I2C and
  `--verify` reads back and compares. What has still not been exercised on
  hardware is the `[pll]` block, `[fpga]` and `[sequence]`.
- `example.toml` is an example of the format, **not** this bench's
  configuration: it enables all 11 serial links, resets the SAMPA and
  configures a chip 1 that does not exist here. Use `bench.toml`.

---

## A note about timing

`Form1.cs` fires I2C commands back to back without checking anything, and it
works because each of its UART writes takes ~700 µs while the I2C transaction
takes ~40 µs. Over the bridge a write takes ~100 ns, so that slack disappears:
here you must always wait for the `i2c_master` to finish. That is what
`i2c_wait_done()` in `sampa_hw.c` does.

The same trap bit the PLL: `pll_commit()` used to write the start and read the
status once, which caught it busy and failed a change that was actually fine.
It now polls.

## See also

- [DAQSTAT.md](DAQSTAT.md) — the DAQ status and acquisition tool
- [SNIFF.md](SNIFF.md) — receiving the data on the PC
- [CSV.md](CSV.md) — the data columns, for whoever analyses them
