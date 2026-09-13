# The SAMPA data files

This document is for whoever is going to **analyse** the data and does not
need to know anything about the hardware, the board, or how the packets get
there.

They are produced like this:

```
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 --csv run1 --csv-long --save run1.bin
```

or, if you already have a capture on disk:

```
python3 sampa_sniff/sampa_sniff.py -f run1.bin --csv run1 --csv-long -q
```

Two files come out. The first always; the second only with `--csv-long`.

### Always keep the `.bin`

`--save` also writes the stream exactly as it arrived, uninterpreted. It is
worth using every time, for two reasons:

- **It takes far less space.** In a real capture: 4.7 MB of `.bin` against
  11.4 MB of `_packets.csv` and 123 MB of `_samples.csv`.
- **It is the only lossless copy.** The CSV files already carry an
  interpretation on top (how the signal was compressed, how the 10-bit samples
  are unpacked). If that interpretation turned out to be wrong, there is no
  way back from the CSV; from the `.bin` everything is regenerated with `-f`.

Think of the `.bin` as the archive and the CSV files as the working copy.

### And if you would rather not produce the CSV files at all

You do not have to. `sampa_data.py` opens the `.bin` and gives you the same
table in memory, with the same columns:

```python
import sampa_data as sd

pk = sd.packets("run1.bin")       # one row per packet
sm = sd.samples("run1.bin")       # one row per sample
df = pk.df()                      # the same thing as a pandas DataFrame
```

The long tables are big, so you can filter while reading and never build the
whole thing:

```python
sd.samples("run1.bin", channel=3)
sd.samples("run1.bin", channel=3, readout=(0, 50))
```

It works without pandas too: walk the table with a `for` loop, pull one column
with `.column("adc")`, or dump it with `.csv("file.csv")`.

The only column that is missing is `received_utc`: that is the time the PC
received the packet, and the binary does not store it. It said nothing about
the physical instant of the measurement anyway — that is what `readout` and
`t_us` are for.

### A quick look, without programming anything

```
python3 sampa_sniff/sampa_view.py run1.bin
```

writes `run1.html`: a self-contained page with all 32 channels in a grid,
which opens with a double click and needs nothing installed. Four views:

- **waveform** — the highest-amplitude window of each channel
- **amplitude over time** — the peak of each readout, scrolling
- **ADC spectrum** — histogram of every value seen; a channel at rest gives a
  narrow peak at its baseline
- **peak amplitude** — histogram of the highest value per window; this is what
  separates channels carrying signal from channels sitting in noise

Click any chart to open it large, with `wheel` to zoom, `drag` to pan and a
cursor that reads out values.

### The same view, but live

```
python3 sampa_sniff/sampa_sniff.py 10.0.163.205 1000 -q --web --board
```

serves the same page at `http://127.0.0.1:8080/`, updating as data arrives,
plus a **Board status** section. Details in [SNIFF.md](SNIFF.md).

---

## What a "packet" is

The detector has **32 channels**. Each channel digitises its signal 10 million
times per second and groups it into windows of about 1000 samples. Each window
of each channel is sent as one **packet**.

A sample is an integer from 0 to 1023: the output of a 10-bit
analogue-to-digital converter. It has no physical units; it is "ADC counts".
At rest a channel sits at its baseline, typically between 50 and 110 counts,
and a real signal appears as a peak above that line.

Not every packet carries data. Many arrive empty, and that is normal (see the
`type` column).

---

## The time axis

This is the first thing to understand, because it is the easiest thing to get
wrong.

There are **two scales** and they combine:

- **`t`** — inside a window. The sample number, from 0 to ~1000. One sample
  every **0.1 µs**. This is the x axis of the waveform.
- **`readout`** — between windows. A counter that goes up by one every time
  the chip dumps all 32 channels, once every **100 µs**.

The files already carry both combined into absolute microseconds from the
start of the capture, so you do not have to compute anything:

| column | where |
|---|---|
| `t_us` | in the samples file: the instant of that sample |
| `t_us_start` | in the other two: the instant the window starts |

**Use `t_us` as the x axis. Do not use `bx` and do not use the row number.**

Why `bx` will not do: it is the accelerator's counter, 20 bits wide, and it
**wraps every 26 milliseconds**. In a capture longer than 26 ms it starts over
from zero, so two measurements milliseconds apart can show the same `bx`. It
is still useful for telling which packets are simultaneous *within one
readout*, but as a time axis it lies.

Why the row number will not do either: see the warning about gaps at the end.

---

## `run1_packets.csv` — one row per packet

| column | what it is |
|---|---|
| `packet` | sequential number within the capture. Use it to cross-reference the other file |
| `received_utc` | when the computer received it. **Not** the physical instant of the measurement, only of reception |
| `chip` | which chip sent it. With a single chip, always 0 |
| `channel` | detector channel, 0 to 31 |
| `type` | see the table below |
| `type_num` | the same type as a number, in case it helps |
| `readout` | dump number of the 32 channels, starting at 0. One every 100 µs. **This is the reliable time reference** |
| `bx` | accelerator clock ("bunch crossing"). Every packet of one readout shares it. Careful: it wraps every 26 ms, so it is no time axis |
| `t_us_start` | the instant this window starts, in microseconds from the start of the capture |
| `format` | how the signal was encoded: `zs`, `raw`, `sum`, `empty`, `undecodable` or `huffman-undecoded`. See below |
| `n_samples` | how many samples this packet carries. 0 in the empty ones |
| `n_clusters` | in how many chunks the signal arrived. 1 is normal |
| `t_start` | the instant, inside the window, where the first sample begins. Normally 0 |
| `sum` | sum of every sample in the packet. Proportional to the collected charge |
| `max_adc` | value of the highest sample. Useful to separate channels with signal from channels at rest |
| `truncated` | 1 if the packet was cut because it did not fit through the link |
| `heartbeat` | 1 if it is a synchronisation heartbeat, with no data |
| `trigger_early` | 1 if the trigger arrived early |
| `fifo_full` | 1 if a queue overflowed inside the hardware |
| `header_ok` | 1 if the packet passed the integrity checks. **If it is 0, distrust that row** |
| `samples` | the samples, separated by spaces |

### Why the samples all go in one column

Because their number changes from packet to packet: 0 in the empty ones, ~1000
in the data ones. One column per sample would give a 1024-column table that is
almost entirely empty. In pandas:

```python
import pandas as pd
df = pd.read_csv("run1_packets.csv")
data = df[df.type == "data"]
waves = data.samples.str.split().apply(lambda v: [int(x) for x in v])
```

### The `format` column

The chip can compress the signal in four different ways, and the receiver has
to know which one to decode it. Normally it is `zs`, which is the default.

| value | meaning |
|---|---|
| `zs` | zero suppression: only the part of the window with signal is sent |
| `raw` | the whole window, uncompressed |
| `sum` | only the total charge of each chunk, without the individual samples. The `samples` column comes out empty and you use `sum` |
| `empty` | the packet carried no signal (heartbeat, truncated) |
| `undecodable` | **careful**: the mode given does not match what arrived |
| `huffman-undecoded` | the chip compressed with Huffman, and nobody knows how to undo it: neither this program nor the original `SAMPA_analyzer` |

If you see `undecodable`, the receiver was run with the wrong mode. The data
is not corrupt: redo the conversion with the right `--mode`. It prefers to
warn rather than return invented numbers.

`huffman-undecoded` is different: there is nothing to retry there. The chip
compressed the samples with variable-length codes and its code table would be
needed to recover them. The rows arrive with their channel and their window,
but with no samples. They are flagged this way, and not another, so nobody
confuses them with a silent channel.

### The `type` column

| value | meaning | carries samples? |
|---|---|---|
| `data` | a complete window of one channel | yes |
| `truncated` | the channel did not fit through the link in that window | no |
| `heartbeat` | synchronisation heartbeat | no |
| `trigger-early` | the trigger arrived early | sometimes |
| `SYNC` | synchronisation pattern | no |

**It is normal for most packets to be `truncated`.** In a typical capture it
is around 60 %. That is neither an error nor corrupt data: the chip produces
more information than fits through its four links, so in each window only some
channels arrive whole, and it rotates between them. For analysis, **keep the
rows of type `data`** and treat the rest as absence of measurement, not as
zeros.

---

## `run1_samples.csv` — one row per sample

The same content in long format, which is usually more convenient:

| column | what it is |
|---|---|
| `packet` | links back to the previous file |
| `readout`, `chip`, `channel`, `bx` | the same as there, repeated on every row |
| `t` | sample number inside the window, starting at 0 |
| `t_us` | **the x axis**: the instant of this sample, in microseconds from the start of the capture |
| `adc` | the value, 0 to 1023 |

To plot one channel's signal:

```python
import pandas as pd
df = pd.read_csv("run1_samples.csv")
df[df.channel == 3].plot(x="t_us", y="adc")
```

It takes a fair amount of space: about 85 MB per 5 MB of capture. If you only
need metadata or a handful of waveforms, the first file is enough.

---

## `run1_clusters.csv` — one row per signal chunk

Optional, with `--csv-clusters`. When zero suppression is on, a channel's
signal can arrive split into several chunks separated in time. This file puts
one per row:

| column | what it is |
|---|---|
| `packet` | links back to the first file |
| `readout`, `chip`, `channel`, `bx` | the same as there |
| `cluster` | chunk number inside the packet, starting at 0 |
| `t_start` | sample number, inside the window, where the chunk begins |
| `t_us_start` | the same in absolute microseconds, ready to plot |
| `size` | how many samples it has |
| `sum` | sum of its samples |

In the current captures a single chunk per packet comes out, covering the whole
window, so it adds little. It becomes meaningful once zero suppression with a
threshold is enabled, which is when the signal really starts arriving in
chunks.

---

## Things to keep in mind

**Group by `readout`, not by `received_utc` and not by `bx`.** The `readout`
is what tells you which measurements are simultaneous. The computer's
timestamp only reflects when the data came in over the network, and `bx` wraps
every 26 ms.

**A channel missing from a readout is not a zero.** It means that measurement
never arrived. Filling with zeros will invent signals that do not exist.

**A channel's rows are NOT contiguous in time.** This is the most expensive
mistake and the easiest one to make. Any given channel only carries data in
about 40 % of the readouts; the rest come out truncated. If you filter by
channel and plot the samples in the order they appear, you are gluing together
windows separated by 100, 200 or even 1000 µs as if they followed one another:
pulses will land where they never happened and the distances between them will
be invented. Nothing in the file warns you, because every row is individually
correct.

The fix is simply to **use `t_us` as the x axis**. The gaps then show up as
gaps and the plot comes out right.

**Baselines differ from channel to channel.** They run from about 50 to about
110 counts. If you are going to compare channels with each other, subtract
each one's own baseline (the median of its samples at rest is a good
estimate).

**Channels 10 and 23 of this chip are dead.** They deliver their packets
normally, but always with the same ADC value — 72 and 101 — with a standard
deviation of exactly zero. Their configuration was checked and is identical to
that of the healthy channels, so it is the silicon: two bad ADCs in a
prototype. Do not use them, and do not try to explain their "signal": there
is none.

**Discard rows with `header_ok = 0`.** They should be zero or nearly zero; if
many show up, there is a problem in the data taking and it is worth raising it
before analysing any further.

---

## See also

- [SNIFF.md](SNIFF.md) — the receiver that produces these files
- [DAQSTAT.md](DAQSTAT.md) — starting the acquisition on the board
- [CONFIG.md](CONFIG.md) — configuring the chip
