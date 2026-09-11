# daqstat — manual

A command-line tool that runs **on the board** (Linux on the HPS) and reads
and pokes the DAQ registers inside the FPGA. It does what the *Run Control*
tab of the Windows GUI does, without Windows and without a serial port.

It exists for two reasons: the board's BusyBox has no `devmem` applet, and a
dump of bare numbers tells you nothing — what you need to know is whether the
serial links are in sync and which step is missing.

```
daqstat  ──/dev/mem + mmap 0xFF200000──>  h2f_lw bridge  ──>  the FPGA's CNC and DM blocks
```

It must be run **as root**: it uses `/dev/mem`.

---

## Reference

```
daqstat                          interpreted DAQ status
daqstat ADDRESS [N]              read N 32-bit words starting at ADDRESS
daqstat -w ADDRESS VALUE         write one word
daqstat links {MASK|auto}        enable serial links (bits 0-10) and DAS (bit 11)
daqstat acquire [N]              start a burst of N packets PER LINK
daqstat trigger                  event trigger              (CMD_REG[15:0] = 3)
daqstat bxsync                   bunch-crossing sync                     (= 5)
daqstat reset                    SAMPA reset                             (= 2)
daqstat fifoclear                clear the FIFO-full flag
daqstat fakeclient {on|off}      fake a TCP client (debugging only)
daqstat -h | --help              short help
```

Valid addresses run from `0xFF200000` to `0xFF203FFF`, the span of the bridge.

### Exit status

| Code | Meaning |
|---|---|
| `0` | all good |
| `1` | failure talking to the FPGA (bus error), or no link in sync with `links auto` |
| `2` | usage error: unknown command, missing arguments, or address outside the bridge |

### Useful addresses

| Register | Address | What it is |
|---|---|---|
| `CNTRL_REG` | `0xFF201000` | link enables and the `acquire` count |
| `STATUS_REG` | `0xFF201068` | per-link sync flag |
| `EDGE_SEL_REG` | `0xFF201098` | per-link sampling edge and delay |
| `CMD_REG` | `0xFF20000C` | commands to the SAMPA |
| `SMP_CFG_REG` | `0xFF200030` | SAMPA configuration as seen by the FPGA |
| `VER_REG` | `0xFF20003C` | firmware version |
| PLL (N, M) | `0xFF20200C` | PLL dividers: N and M |
| PLL (C0..C4) | `0xFF202028` | dividers for adc, bx, so, rad_slvs, aux |

---

## The whole thing in three steps

This is the complete order, from nothing to data. All three steps are needed
and the order matters:

```sh
# 1. On the PC (or on the board), BEFORE anything else: somebody must listen
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 --web --save run1.bin

# 2. On the board: enable the links that are in sync
./daqstat links auto

# 3. On the board: start a burst
./daqstat acquire 2048
```

And `./daqstat` on its own at any time to see what is going on.

Why that order: **with no client on port 1000 the FPGA pushes nothing.** That
is by design, not a fault. `sampa_server` sets bit 0 of the HPS register when
it accepts the connection, and that bit gates the whole readout path.

---

## Reading the status dump

`./daqstat` with no arguments prints five blocks. Here is what each one means.

### FPGA

```
  firmware version     : 804
```

Comes from `VER_REG`. If it shows `0` or `4294967295` the FPGA is not
configured (the `.rbf` was never loaded), and it says so. Below 700 is old
firmware.

### sampa_server

```
  HPS register         : 0x0002FA01
  server version       : 762
  client connected     : YES
```

A single word carrying two things: bit 0 is *client connected* and the upper
bits hold the server version. If it says `NO`, the FPGA will send nothing even
if everything else is perfect.

### acquisition

```
  CNTRL_REG            : 0x0800000F
  DAS path (DDR3)      : OFF
  packets to acquire   : 2048 per link  (256 readouts, 25.6 ms)
```

`CNTRL_REG` is the key register and worth being able to read at a glance:

| Bits | What it is |
|---|---|
| `[10:0]` | enable bits for the eleven serial links |
| `[11]` | enable for the DAS path (DDR3) |
| `[12]` | start pulse (given by `acquire`) |
| `[13]` | pulse to clear the FIFO-full flag |
| `[31:16]` | how many packets to acquire, **per link** |

So `0x0800000F` reads as: `0x0800` = 2048 packets, and `0x00F` = links 0, 1, 2
and 3 enabled. And `0x08000000` — a state that is easy to end up in — means
2048 packets and **no link enabled**: `acquire` works but not a single packet
comes in.

The *per link* part matters: each link carries 8 channels, so one readout of
all 32 channels costs 8 packets. `N` packets are `N/8` readouts and
`N × 12.5 µs` long. The field is 16 bits wide, so the maximum is 65535 packets
≈ 819 ms.

**The DAS and the serial links are mutually exclusive.** In the GUI, ticking
DAS unticks all eleven links and vice versa. `daqstat links` enforces this by
itself: if you pass a mask with both, it keeps DAS and says so.

### serial links

```
   link  enabled  sync  fifo-full    packets  sync-loss  dropped  trunc
   0     yes      yes   no          19844371          0        0      0
```

Column by column:

| Column | Where it comes from | What it means |
|---|---|---|
| `enabled` | `CNTRL_REG[i]` | you turned it on with `links` |
| `sync` | `STATUS_REG[i]` | the deserialiser found the sync pattern |
| `fifo-full` | `STATUS_REG[12+i]` | the FIFO filled up at some point (sticky; cleared with `fifoclear`) |
| `packets` | `DM_PKT0+i` | packets counted |
| `sync-loss` | `DM_SYNC0+i` | losses of synchronisation |
| `dropped` | `DM_DROP0+i` | packets dropped |
| `trunc` | `DM_TRUNC0+i` | packets truncated |

`sync yes` with `enabled NO` is normal right after boot: the link works, it
just has not been switched on. The other way round (`enabled yes`, `sync NO`)
is a clock or chip-configuration problem.

One thing that misleads people: **`trunc` at zero does not mean nothing is
being lost.** The truncation you see in the data happens *earlier*, inside the
SAMPA: the chip produces 3.2 Gbit/s and the four e-links only carry
1.28 Gbit/s. With all 8 channels per link enabled about 60 % is lost there,
and the FPGA never sees it because it never arrived.

### what to look at

The last block is a diagnosis: it looks at the state and says what to do next.
The cases it recognises:

| What it says | What to do |
|---|---|
| `NO link is in sync` | SAMPA clock, DM serial links, or the configuration was never applied |
| `Some links are in sync but NONE is enabled` | `daqstat links 0x00F` (it gives you the mask, already worked out) |
| `DAS and serial links enabled at once` | they are exclusive; `daqstat links` with only one of the two |
| `there is no client on port 1000` | start the sniffer, or `daqstat fakeclient on` to test without it |
| `The packet counter to acquire is zero` | `daqstat acquire 2048` |
| `Links enabled and in sync` | all set; if the counters do not rise, `acquire` + `bxsync` + `trigger` |

When you do not know what to do, that block usually gets it right. Read it
before investigating on your own.

---

## Commands

### Status and raw reads

```sh
./daqstat                  # the interpreted dump above
./daqstat 0xFF20003C       # read a single address (like devmem)
./daqstat 0xFF201000 16    # read 16 consecutive words
./daqstat -w ADDR VAL      # write one word
```

Addresses must fall inside the bridge (`0xFF200000`–`0xFF203FFF`); if you go
outside, it says so rather than crashing.

### links

```sh
./daqstat links 0x00F      # links 0..3
./daqstat links 0x800      # the DAS path (DDR3) only
./daqstat links auto       # whichever links are in sync right now
./daqstat links 0          # disable all of them (it warns first)
```

Writes bits `[11:0]` of `CNTRL_REG`. `auto` reads `STATUS_REG` and enables
exactly the synchronised ones, so you do not depend on a hand-written mask.

It only accepts a number (decimal, `0x` hex or octal) or the word `auto`.
Anything else is rejected — and there is a story behind that, see below.

### acquire

```sh
./daqstat acquire          # 2048 packets per link
./daqstat acquire 8192     # 8192 per link = 1024 readouts = 102.4 ms
```

Writes the count into `CNTRL_REG[31:16]` and gives the start pulse
(`CNTRL_REG[12]`).

**It is one-shot.** The burst ends by itself once N packets have been
acquired; to keep taking data you must issue `acquire` again. The counters do
not start rising on their own, and that is not a fault — it is what starting a
burst means.

`acquire 0` means zero packets, not "unlimited". It warns about that.

If the DAS is active it also pulses `SMP_CFG_REG[20]` from 0 to 1 around the
start to re-synchronise it, exactly as the GUI does.

### Commands to the SAMPA

```sh
./daqstat trigger          # event trigger        (CMD_REG[15:0] = 3)
./daqstat bxsync           # bunch-crossing sync              (= 5)
./daqstat reset            # SAMPA reset                      (= 2)
```

### Utilities

```sh
./daqstat fifoclear        # clear the sticky FIFO-full flag
./daqstat fakeclient on    # fake a TCP client (bit 0 of the HPS register)
./daqstat fakeclient off
./daqstat -h
```

`fakeclient` lets you exercise the FPGA → DDR3 path with nobody listening.
Note that `sampa_server` overwrites that bit when it accepts or closes a
connection, so it does not survive a real client coming or going.

---

## Building and copying

The board is ARM and the PC is x86, so it has to be cross-compiled. The
toolchain and the whole setup are covered in `README.md`; for `daqstat`:

```sh
make daqstat        # builds bin/daqstat, a static ARM binary
file bin/daqstat    # ELF 32-bit LSB, ARM  <- check this
scp bin/daqstat root@10.0.163.205:/home/root/
```

---

## Troubleshooting

**First of all: is the SAMPA powered?** Its card has a supply of its own,
separate from the SoC board, and it does not come back by itself after a
mains cut. The SoC boots normally, the FPGA loads, every register reads
fine, and the chip is simply off. The signature is below, under *the
i2c_master does not respond*. On 2026-09-11 this cost a full afternoon of
resets, a `.jic` reflash and a hung bridge before somebody pressed the
button on the supply.

**The i2c_master does not respond (TIMEOUT), and what it is not.**
`sampa_cfg` reports two different failures and they mean opposite things:

| Message | Meaning |
|---|---|
| `the i2c_master did not respond` (TIMEOUT) | the state machine inside the FPGA never finished: `COM_REG[7:1]` never cleared |
| `the SAMPA did not answer` (NACK) | the master finished cleanly and the chip did not acknowledge |

A TIMEOUT is not the chip refusing: it is the transfer never happening.
Dump the block to see why (it lives at `OFF_I2C = 0x3000`, one register
every 4 bytes):

```sh
./daqstat 0xFF203000 7      # PRE CTR ADD TX RX COM STA
```

| Reading | Meaning |
|---|---|
| `PRE = 0x0D`, `CTR = 0x02` | prescaler and core enable correct; `sampa_cfg` writes them on every run |
| `COM` non-zero | a command is still in flight: the transaction hung |
| `STA = 0x03` — `TIP = 1`, `BUSY = 0` | the master never managed to put a START on the bus, which needs SCL **high**. Either the chip is holding SCL low, or **the bus pull-ups have no power** — from software the two look identical, only a meter on SCL separates them |
| `ADD` and `TX` unchanged across several attempts | the block is frozen: it is not even accepting register writes. Different fault from the one above |

**A chip that has just been powered on needs a soft reset before it is
configured.** Otherwise its serial outputs come up half dead: links report
`sync yes` and count zero packets, `ERRORS` reads `0xF0` (7 uncorrectable
header Hamming errors, the maximum the 3-bit field holds), and a single
channel arrives. Every register reads correct, because the registers are
not the problem — the order is. The recipe, verified on 2026-09-11:

```sh
./sampa_cfg write 0 CMD 5              # SOFTRST
./sampa_cfg --verify apply bench.toml  # the reset may clear registers
./sampa_cfg dump 0                     # confirm CHEN0..3 and SOCFG
./sampa_cfg write 0 CMD 6              # LNKSYNC
./daqstat acquire 2048
```

Reset, configure, **then** synchronise. `ERRORS` went to `0x00` and the four
links started counting 4097 packets each, which is what one `acquire 2048`
delivers.

**Never write `CMD_REG = 1` (reset all).** `./daqstat -w 0xFF20000C 1` hangs
the h2f_lw bridge: the store never completes, the process is stuck in an
uninterruptible wait, and the board is gone until somebody cuts the power.
`daqstat` deliberately exposes only `reset` (= 2), `trigger` (= 3) and
`bxsync` (= 5).

**The buttons on the bench** (from `trunk/hdl/SAMPA_FPGA_test_board.vhd`):

| Control | Line | What it does |
|---|---|---|
| KEY4 / `RESET_n`, pin AD27 | 923 | `sampa_Hrstb <= sampa_Hrstb_int and RESET_n` — hard reset of the chip. Same pin `daqstat reset` drives, but the button can be **held** |
| `PORin` | 929 | **commented out**: the FPGA cannot give the chip a power-on reset. Only cutting its power does that |
| KEY3 | 1049 | freezes the SO clock while held low |
| SW3 / LED3 | 43 | the internal/external SAMPA selector does nothing: `test_mode = 0` in this build |

**Links half up, or all in sync but with the counters stuck at zero: power
cycle the board.** It is the only recipe that has worked, and it is verified.
Symptoms: only some links show `sync yes`, or every link is in sync but the
`packets` counters stay at zero while the chip still produces heartbeat
packets.

The complete FPGA registers (all of CNC and all of DM) and the chip registers
were dumped in a broken boot and in a good one, and **they are identical**:
same `EDGE_SEL_REG` (0x1D0), same `SMP_CFG_REG`, same `VACFG`, same `SOCFG`,
same `CHEN`. There is no register to fix, so **do not waste time on
configuration**: rebooting Linux is not enough, the power has to go away for a
few seconds. In one afternoon the sampling edge and delay (all four
combinations), `slvs_enable`, the heartbeat trigger, the PLL dividers and the
error clear were all tried without success; the power cycle fixed it first
time.

Before calling a boot good, check that `STATUS_REG` reads `0x0000000F` and
that all four links are counting packets. If not, power-cycle again.

**Links stuck at `sync NO` and `STATUS_REG = 0x00000000`.** The FPGA
deserialisers have come unlocked and nobody has re-emitted the sync pattern.
This happens, for instance, after touching `VACFG`: switching continuous mode
off stops the chip transmitting, and switching it back on makes it send data
again but does **not** regenerate the pattern. You have to ask for it:

```sh
./sampa_cfg write 0 CMD 6      # LNKSYNC (table 3.3 of the specification)
./daqstat                      # STATUS_REG should go back to 0x00F
```

The SAMPA's `CMD` register (0x0E) returns to 0 by itself once the command has
run. `0x6` is *"Generates sync packet on serial links"*.

**Do not run `sampa_cfg fixsync` on this board.** It has destabilised working
links several times, and the reason is now known: it mirrors
`btFixSync_Click` from the GUI, which before measuring writes `SOCFG = 0x1b`
(eleven serial outputs instead of this board's four) and `CHEN0..3 = 0xff`
(all 32 channels). It walks over your chip configuration to run its sweep, and
does not put it back.

**A typo in the command used to be read as an address.** `daqstat aquire`
(missing the `c`) did not say "unknown command" but `address outside the
bridge`, because it fell through to the read-an-address branch and
`strtoul("aquire")` is 0. Fixed: it now names the command it does not know and
prints the help. If you still see the old message, **the binary on the board
is out of date**.

**`CNTRL_REG` stays as you left it.** The enable bits persist between runs. If
an earlier session set them to zero, you still have no links today without
having touched anything.

**Packets go up once and then stop.** That is `acquire` doing its job: the
burst finished. Issue another one.

**BUS ERROR while talking to the FPGA.** The `mmap` worked but nobody answers
on the other side: either the FPGA is not configured (missing `.rbf`), or the
`lwhps2fpga` bridge is disabled. `daqstat` catches the `SIGBUS` and explains
it instead of dying with a bare "Bus error", because that failure *is* the
diagnosis.

---

## Files

| File | What for |
|---|---|
| `/dev/mem` | access to the FPGA registers. This is why root is needed. |
| `daq_init.sh` | startup script: waits for sync, then `links auto`, `acquire` and `bxsync` |

## See also

- [SNIFF.md](SNIFF.md) — the receiver on the other side of port 1000
- [CSV.md](CSV.md) — what comes out of the data, for whoever analyses it
- [CONFIG.md](CONFIG.md) — `sampa_cfg`, the chip configuration
