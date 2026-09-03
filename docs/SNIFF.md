# sampa_sniff — manual

Receives the data `sampa_server` sends from the board, decodes it, and puts it
somewhere you can use: on screen, in CSV files, in a lossless `.bin`, or in a
web view that updates live.

It is the day-to-day replacement for `SAMPA_analyzer`. It uses only the
**Python 3 standard library**: nothing to install, just copy the file and run
it — on Linux, on the lab's Windows box, or on the board itself pointing at
`127.0.0.1`.

```
FPGA ──> sampa_server (port 1000) ──> sampa_sniff ──┬──> screen
                                                    ├──> .bin  (lossless)
                                                    ├──> .csv  (for analysis)
                                                    └──> http://localhost:8080
```

---

## Reference

```
sampa_sniff.py [OPTIONS] [HOST] [PORT]
```

`HOST` defaults to `10.0.163.205` and `PORT` to `1000`. It **runs on the PC**
and needs only Python 3 with the standard library: no `pip`, no virtual
environment, no dependencies. It behaves the same on Linux and on Windows.

> **One client only.** `sampa_server` does `listen(sock, 1)`. While
> `sampa_sniff` is connected, neither the Windows GUI nor `SAMPA_analyzer` can
> get in. And vice versa.

### All the options

| Option | Argument | Default | What it does |
|---|---|---|---|
| `-f`, `--file` | FILE | — | read a capture from disk instead of the network |
| `-t`, `--timeout` | SECONDS | 5, or 0 with `--web` | seconds to wait with no data. `0` = no limit |
| `-n`, `--count` | N | 0 | stop after N packets. `0` = no limit |
| `-q`, `--quiet` | — | no | no line per packet, only the summary |
| `-s`, `--samples` | [N] | 16 if given bare | show the first N samples |
| `-H`, `--header` | — | no | show the raw header |
| `--chip` | N | — | filter by chip (hadd) |
| `--channel` | N | — | filter by channel |
| `--only-problems` | — | no | only suspicious packets |
| `--raw` | N | — | dump the first N words uninterpreted, then exit |
| `-d`, `--duration` | TIME | — | capture for exactly this long, then stop |
| `--save` | [FILE] | — | save the stream losslessly. With no name, one is built from the run's start and end times |
| `--zs` | COUNTS \| off | — | set the zero-suppression threshold on the chip, in ADC counts. Needs `--board` |
| `--zs-pre` | N | 1 | samples kept before each pulse, 0 to 3 |
| `--zs-post` | N | 2 | samples kept after each pulse, 0 to 7 |
| `--allow-writes` | — | no | let the web page record and change the chip. Binds the server to 127.0.0.1 |
| `--record-dir` | DIR | `.` | where recordings started from the page are written |
| `--sampa-cfg` | PATH | `./sampa_cfg` | where `sampa_cfg` lives on the board |
| `--csv` | PREFIX | — | write `PREFIX_packets.csv` |
| `--csv-long` | — | no | also `PREFIX_samples.csv`, one row per sample |
| `--csv-clusters` | — | no | also `PREFIX_clusters.csv` |
| `--mode` | auto\|zs\|raw\|sum\|huffman | auto | how the payload is compressed |
| `--web` | [PORT] | 8080 | serve the live view over HTTP |
| `--board` | [USER@IP] | `root@<host>` | add the DAQ status, running `daqstat` over ssh |
| `--daqstat` | PATH | `./daqstat` | where `daqstat` lives on the board |
| `-h`, `--help` | — | — | help |

### Exit status

| Code | Meaning |
|---|---|
| `0` | finished cleanly, even if no packet ever arrived |
| `1` | could not resolve the host, connect, open the input or output file, or open the web port |

### Files it needs and produces

| File | When |
|---|---|
| `sampa_view.py`, `sampa_data.py` | **required** for `--web`, in the same directory |
| `FILE.bin` | with `--save`. The lossless copy; reprocess it with `-f` |
| `PREFIX_packets.csv` | with `--csv` |
| `PREFIX_samples.csv` | with `--csv-long` |
| `PREFIX_clusters.csv` | with `--csv-clusters` |

---

## Getting started

### Just see whether anything arrives

```sh
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000
```

One line per packet. `Ctrl-C` stops it and prints the summary.

### A real run

This is what you will want almost every time:

```sh
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 -q --save run1.bin --web
```

- `-q` does not print a line per packet (there are thousands per second)
- `--save` keeps the lossless copy
- `--web` brings up the live view at `http://localhost:8080/`

Then, in **another terminal** on the board, start the acquisition
(`daqstat links auto` and `daqstat acquire 2048` — see [DAQSTAT.md](DAQSTAT.md)).
Order matters: the FPGA pushes nothing until a client is connected, so
**`sampa_sniff` goes first**.

### Produce the CSV files later, without going back to the board

```sh
python3 sampa_sniff/sampa_sniff.py -f run1.bin --csv run1 --csv-long -q
```

`-f` reads from the file instead of the network. The decoding is exactly the
same, so you can reprocess a capture as often as you like.

---

## Timed captures

A run of an exact length, which is what an experiment usually needs:

```sh
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 -q --duration 30m --save
```

`--duration` accepts the two shapes people actually write:

| Form | Examples |
|---|---|
| clock | `01:30:00` (1 h 30 min), `90:00` (90 min), `2:30` (2 min 30 s) |
| suffixes | `45s`, `5m`, `2h`, `1h30m`, `2h5m30s` |

A bare number is seconds.

The stop time is measured with a **monotonic** clock, so an NTP correction or
a daylight-saving change in the middle of a long run cannot stretch or shorten
the experiment. It is also checked during silent stretches: if the board sends
nothing for a while, the capture neither gives up early nor overruns.

### The file names itself after the experiment

`--save` with no name builds one from the wall-clock times of the run:

```
sampa_2026-09-01_1430-00_to_1500-00.bin
```

Date first, so `ls` sorts chronologically. While the run is in progress the
end time is not known yet, so the file is opened as `..._to_RUNNING.bin` and
renamed when it closes — which means the name always carries the **real** end
time, even if you cut the run short with Ctrl-C.

Giving `--save a_name.bin` still works exactly as before.

---

## Zero suppression

Zero suppression happens on the **chip**, not in this receiver, and its three
registers do not say what they mean:

| Register | What it is | The trap |
|---|---|---|
| `ZSTHR` | the threshold, 12 bits | it is in **quarters** of an ADC count. A threshold of 100 is written as 400 |
| `ZSCFG` | configuration, 9 bits | `[1:0]` glitch filter, `[4:2]` post-samples, `[6:5]` pre-samples, `[8]` raw output |
| `VACFG` | bit 1 | while this is 1 the chip sends whole windows and the threshold does nothing at all |

Get any one of the three wrong and it looks exactly like "zero suppression
does not work". So you give a threshold in ADC counts and how many samples to
keep around each pulse, and the rest is worked out for you:

```sh
# threshold 100 ADC counts, 1 sample before the pulse and 2 after
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 --board --zs 100

# more context around each pulse
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 --board --zs 100 --zs-pre 3 --zs-post 7

# off: send whole windows again
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 --board --zs off
```

It runs **before** connecting, so if the configuration fails nothing is
captured and the single client slot on port 1000 is not taken. Ranges are
checked before anything is written: a threshold above 1023.75 counts, or
pre/post outside 0-3 and 0-7, is refused with a message rather than silently
truncated.

`--zs` needs `--board`, because the threshold is written over ssh with
`sampa_cfg`, not by this receiver.

### From the web page

With `--allow-writes` the live view grows a **Zero suppression** panel: three
boxes (threshold, pre, post), *apply* and *turn off*, plus a button to start
an `acquire` burst. It echoes back the registers it wrote.

```sh
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 -q --web --board --allow-writes
```

> **Writing is off by default, and switching it on changes where the server
> listens.** A read-only view can be served to the whole lab: the worst a
> visitor can do is look. As soon as the page can write to the chip that stops
> being true, so with `--allow-writes` the server binds to **127.0.0.1 only**
> and you reach it through an ssh tunnel:
>
> ```sh
> ssh -L 8080:127.0.0.1:8080 USER@THE_LAB_PC
> ```
>
> The check is enforced on the server too, not just by hiding the buttons:
> without the flag, `/control` answers 403. A stale browser tab cannot poke
> the chip either.

### Recording from the page

With `--allow-writes` the live view grows a **Record an experiment** panel:
type a duration, press **record**, and the raw stream is written to a `.bin`
for exactly that long.

```sh
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 -q --web --allow-writes \
        --record-dir /data/runs
```

While it runs the panel shows elapsed time, megabytes written, time left and a
progress bar, and the button becomes **stop** so a run can be cut short. Leave
the duration empty to record until you stop it by hand.

The file is named after the experiment — when it started, when it ended and how
long it lasted:

```
sampa_2026-09-03_1430-00_to_1500-00_30m00s.bin
```

While recording it is called `..._RECORDING.bin` and is renamed on stop, so the
name always describes what actually happened, even for a run that was cut short
or ended when the receiver shut down. When it finishes, the panel shows the
summary: file, start, end, duration, size, and why it stopped.

The duration accepts the same forms as `--duration`, and is checked in the
browser as well as on the receiver so a typo says so straight away.

**Recording needs no `--board`**: it saves the stream that is already arriving
on port 1000. `--board` is only needed for the chip controls.

---

## Always keep the `.bin`

`--save` writes the stream exactly as it arrived, uninterpreted. Two reasons to
use it every time:

- **It is far smaller.** In a real capture: 4.7 MB of `.bin` against 11.4 MB of
  `_packets.csv` and 123 MB of `_samples.csv`.
- **It is the only lossless copy.** The CSV files already carry an
  interpretation on top (how the signal was compressed, how the 10-bit samples
  are unpacked). If that interpretation turned out to be wrong, there is no way
  back from the CSV; from the `.bin` everything is regenerated.

Think of the `.bin` as the archive and the CSV files as the working copy. And
they are not even required: `sampa_data.py` opens the `.bin` and gives you the
same table in memory (see [CSV.md](CSV.md)).

---

## The output

### One line per packet

```
#1234   chip  0  channel 17  data                   len 1000  bx  524288
```

With `--samples` and `--header` the samples and the raw header are printed
underneath. The flags in brackets (`[truncated]`, `[raw]`, `[trigger-early]`)
come from the header.

### Final summary

```
--- summary ----------------------------------------------
  packets      : 16300  (1250.4/s)
  samples      : 16300000
  bytes        : 8707520  (667.2 kB/s)
  by type      :
      4 data                     16300
  by chip      : 0=16300
  channels seen: 32
  problems     : none
----------------------------------------------------------
```

And with data, a per-channel breakdown: four lines, one per link, giving the
percentage of packets that carried samples, plus the list of channels that saw
none at all. That last part is what you want when you disable channels to gain
bandwidth: it tells you which ones are really transmitting.

### What counts as a "problem"

The same criteria as `SAMPA_analyzer`:

| Warning | What it means |
|---|---|
| `SYNC packet (link out of sync)` | the serial link lost synchronisation |
| `malformed heartbeat` | a legitimate heartbeat is empty, on channel 21 and with parity 0; any other one means lost sync |
| `impossible length (N)` | more than 1026 samples: the header is not a header |
| `bad header parity` | a bit flipped on the way |

`problems : none` over a long run means the FPGA → DDR3 → Ethernet → PC path
lost nothing. The real losses in this chain happen *earlier*, inside the SAMPA
(see [DAQSTAT.md](DAQSTAT.md)).

---

## The live view

```sh
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 -q --web
```

Brings up a server at `http://localhost:8080/` with all 32 waveforms and four
views: **waveform**, **amplitude over time**, **spectrum** and **peak
amplitude**. Click any chart to open it large, with zoom and a cursor.

Data travels over a **WebSocket**. If that fails (an odd proxy, an old
browser), the page falls back to polling every 0.7 s and looks the same.

It needs `sampa_view.py` and `sampa_data.py` **in the same directory**. If they
are missing it says so plainly instead of raising a `ModuleNotFoundError`.
Without `--web`, `sampa_sniff.py` works on its own.

### The board status, inside the same page

```sh
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 -q --web --board
```

Adds a **Board status** section at the bottom of the page: firmware and
`sampa_server` versions, whether a client is connected, which links are
enabled, the `acquire` burst in progress, the table of the eleven links with
their counters, and daqstat's *what to look at* block verbatim. It refreshes
itself every 3 s. The raw dump sits underneath, collapsed.

This does **not** come over port 1000. It is a separate query: the program
calls the system's `ssh` binary and runs `daqstat` on the board. Nothing needs
installing — Windows 10 and every Linux already ship it — but `ssh` to the
board must get in without asking for a password.

`--board` with no value uses `root@<host>`, i.e. the same machine the data
comes from, which is the normal case. With a value it points elsewhere:
`--board root@10.0.163.205`.

If the board does not answer, the section says why (`No route to host`,
`cannot find the 'ssh' program`, `the board did not answer in 10 s`) rather
than going blank. The rest of the page keeps working: the data and the board
view are independent paths.

Without `--board` the section does not appear, and neither does it in an HTML
file saved to disk: there is nobody on the other side to ask.

### Watching it from another computer

If the sniffer runs on the lab PC and you want to watch from your laptop, use
an SSH tunnel:

```sh
ssh -L 8080:127.0.0.1:8080 USER@THE_LAB_PC
```

then open `http://localhost:8080/` in your browser. The WebSocket goes through
the tunnel too; it is just TCP.

**Write `127.0.0.1`, not `localhost`.** That name is resolved by the remote
machine, and on Windows it usually comes out as `::1` first; the server only
listens on IPv4, so with the name the connection is refused even when
everything else is fine. With `-L 8080:localhost:8080` nothing loads and there
is no error message explaining why.

---

## Troubleshooting

**Not a single packet arrives and the sniffer says 0 bytes.** Almost always
the board, not the sniffer: links not enabled in `CNTRL_REG`, or the `acquire`
is missing. Run `./daqstat` on the board and read the *what to look at* block.

**It closes before you have time to type.** The default timeout is 5 s. Use
`-t 120` while you set up the board, or `-t 0`.

**The Windows console freezes.** Not the program: it is the console's
*QuickEdit* mode, which pauses the process when you click inside it. Press
`Esc` or `Enter` to unstick it. To check whether something is still running:
`tasklist | findstr python` and `taskkill /PID N /F`.

**A `ConnectionAbortedError` / `WinError 10053` traceback.** That was noise
from the HTTP server when the browser closed a connection (a reload, switching
tabs). It is silenced now; real errors are still shown.

**Channels 10 and 23 come out flat.** Not a sniffer or configuration fault:
all 31 channel registers are identical to those of their healthy neighbours.
It is dead silicon of an MPW2 prototype. They are harmless; just do not use
them.

---

## See also

- [CSV.md](CSV.md) — the CSV columns and `sampa_data.py`, for whoever analyses
- [DAQSTAT.md](DAQSTAT.md) — the other side: starting the acquisition on the board
- [CONFIG.md](CONFIG.md) — `sampa_cfg`, the chip configuration
