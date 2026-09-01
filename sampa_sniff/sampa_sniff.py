#!/usr/bin/env python3
"""sampa_sniff - look at the packets sampa_server sends, raw.

Connects to the board's sampa_server exactly like SAMPA_analyzer does, but
without ROOT, without windows and without decoding more than necessary: it
prints one line per packet with the header already interpreted.

    python3 sampa_sniff.py 10.0.163.205 1000

It uses only the standard library, so it can be copied as-is to a Windows
machine, or onto the board itself and pointed at 127.0.0.1.

NOTE: sampa_server does listen(sock, 1) and serves ONE client at a time. While
this program is connected, neither the GUI nor SAMPA_analyzer can get in.

The format comes from SAMPA_analyzer.cpp (decode header, ~line 350) and from
tcp_get_data_mpw2 in Form1.cs. A 50-bit header spread over two 32-bit words:

    word 0                             word 1
    [ 5: 0] hamming                    [19: 0] bunchcrossing (bits 20:1)
    [ 6: 6] header parity              [19:19] data parity
    [ 9: 7] type                       [29:20] FIRST sample
    [19:10] length (10-bit samples)    [31:30] unused
    [23:20] hadd  (chip)
    [28:24] chanadd (channel)
    [29:29] bunchcrossing bit 0
    [31:30] fifo full (flag set by the FPGA)

The remaining samples are packed three per 32-bit word.
"""

import argparse
import collections
import errno
import math
import re
import socket
import struct
import subprocess
import sys
import time
import base64
import csv
import datetime
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Packet types, as the analyzer interprets them
TYPE_NAMES = {
    0: "heartbeat",
    1: "truncated",
    2: "SYNC",
    3: "truncated+trigger-early",
    4: "data",
    5: "data+1024",
    6: "trigger-early",
    7: "trigger-early+1024",
}


class Header(object):
    """One packet header, already decoded."""

    __slots__ = ("w0", "w1", "raw", "hamming", "hparity", "type", "len",
                 "hadd", "chanadd", "bunchcrossing", "dparity", "fifo_full",
                 "raw_mode", "first_sample", "len32", "flags", "dropped")

    def __init__(self, w0, w1):
        self.w0 = w0
        self.w1 = w1
        self.raw = ((w1 & 0xFFFFF) << 30) | (w0 & 0x3FFFFFFF)

        self.hamming = w0 & 0x3F
        self.hparity = (w0 >> 6) & 0x1
        self.type = (w0 >> 7) & 0x7
        self.len = (w0 >> 10) & 0x3FF
        self.hadd = (w0 >> 20) & 0xF
        self.chanadd = (w0 >> 24) & 0x1F
        self.bunchcrossing = ((w0 >> 29) & 0x1) | ((w1 << 1) & 0xFFFFF)
        self.dparity = (w1 >> 19) & 0x1

        # the FPGA flags here that its FIFO filled up and dropped the payload
        self.fifo_full = bool(((w0 >> 30) & 0x1) or ((w0 >> 31) & 0x1))
        # raw mode: chip 15 channel 0 does not exist, it is the FPGA's flag
        self.raw_mode = (self.hadd == 15) and (self.chanadd == 0)

        # types 5 and 7 carry an extra 1024 samples
        if self.type in (0x5, 0x7):
            self.len += 1024

        # When the FPGA FIFO filled up, the samples that follow are garbage,
        # but they DO arrive: the FPGA does not set the length to zero. They
        # must be read anyway or we lose sync with the stream. Both original
        # programs do the same (SAMPA_analyzer.cpp and tcp_get_data_mpw2 in
        # Form1.cs): they compute len32 from the header length and only then
        # discard the samples.
        self.dropped = self.fifo_full

        self.first_sample = (w1 >> 20) & 0x3FF if self.len else None
        # the first sample already came with the header; the rest go 3 per word
        self.len32 = int(math.ceil((self.len - 1) / 3.0)) if self.len else 0

        self.flags = []
        if self.type in (0x6, 0x7, 0x3):
            self.flags.append("trigger-early")
        if self.type in (0x3, 0x1):
            self.flags.append("truncated")
        if self.fifo_full:
            self.flags.append("FIFO-LLENA")
        if self.raw_mode:
            self.flags.append("raw")

    @property
    def is_heartbeat(self):
        return self.type == 0x0

    @property
    def is_sync(self):
        return self.type == 0x2

    def problem(self):
        """Return why the packet is suspicious, or None.

        Same criteria as SAMPA_analyzer: a legitimate heartbeat is empty, on
        channel 21 and with data parity 0. Any other heartbeat, or a SYNC
        packet, means the serial link lost synchronisation.
        """
        if self.is_sync:
            return "SYNC packet (link out of sync)"
        if self.is_heartbeat and not (self.len == 0 and self.chanadd == 21
                                      and self.dparity == 0):
            return "malformed heartbeat"
        if self.len > 1026:
            return "impossible length ({0})".format(self.len)
        if not self.raw_mode:
            p = _parity(self.w0 & 0x3FFFFFFF) ^ _parity(self.w1 & 0xFFFFF)
            if p:
                return "bad header parity"
        return None

    def line(self):
        type = TYPE_NAMES.get(self.type, "?")
        s = ("chip {0:2d}  channel {1:2d}  {2:<22s} len {3:4d}  bx {4:7d}"
             .format(self.hadd, self.chanadd, type,
                     0 if self.dropped else self.len,
                     self.bunchcrossing))
        if self.flags:
            s += "  [" + " ".join(self.flags) + "]"
        return s


def _parity(x):
    """Even parity: number of bits set, modulo 2."""
    p = 0
    while x:
        p ^= x & 1
        x >>= 1
    return p


def unpack_samples(header, payload_words):
    """Extract the 10-bit samples from the 32-bit words.

    The first sample travels in the header; from there on they go three per
    word, from the least significant to the most significant.
    """
    if not header.len or header.dropped:
        return []
    samples = [header.first_sample]
    for w in payload_words:
        samples.append(w & 0x3FF)
        samples.append((w >> 10) & 0x3FF)
        samples.append((w >> 20) & 0x3FF)
    return samples[:header.len]


def _clusters_zs(header, samples):
    """Zero suppression: the payload comes in chunks, each preceded by its
    size and by the instant it starts at. Same unpacking as
    SAMPA_analyzer.cpp (~586-615), including the special case of len > 1025.
    Returns [] if the payload does not fit that format."""
    out = []
    i, n = 0, len(samples)
    first = True
    while i < n:
        size = samples[i]
        if first and header.len > 1025:
            size += 1024
        first = False
        i += 1
        if i >= n:
            return []
        t0 = samples[i]
        i += 1
        if size <= 0 or i + size > n:
            return []
        chunk = samples[i:i + size]
        out.append((t0, chunk, sum(chunk)))
        i += size
    return out


def _clusters_sum(samples):
    """Cluster sum (MCH): 4 words per chunk -> size, instant, and the sum.
    SAMPA_analyzer.cpp (~622-656)."""
    out = []
    i, n = 0, len(samples)
    while i + 4 <= n:
        size = samples[i]
        t0 = samples[i + 1]
        sum = (samples[i + 3] << 10) | samples[i + 2]
        if size <= 0:
            return []
        out.append((t0, None, sum))
        i += 4
    return out if i == n else []


def decode(header, samples, mode):
    """Turn the payload into (format, [(t_start, samples, sum), ...]).

    The SAMPA can compress in four ways and the payload format changes with
    each one; VACFG in the chip picks it (bit 1 raw, bit 2 cluster sum,
    bit 3 Huffman; none = zero suppression). Since the receiver may run on a
    different machine and cannot ask the chip, 'auto' tries zero suppression
    and falls back to raw if it does not fit.

    'samples' is None when the mode does not transmit them (cluster sum).
    """
    if not samples:
        return ("empty", [])
    if mode == "huffman":
        # The chip can compress with variable-length codes (VACFG bit 3).
        # Undoing that needs its code table, which we do not have; the
        # original SAMPA_analyzer does not have it either and raises an
        # exception. What matters is not letting 'auto' fall back to raw: it
        # would read the compressed stream as 10-bit samples and produce
        # plausible, meaningless numbers, which is worse than producing
        # nothing.
        return ("huffman-undecoded", [])
    if mode == "raw":
        return ("raw", [(0, samples, sum(samples))])
    if mode == "sum":
        cl = _clusters_sum(samples)
        return ("sum", cl) if cl else ("undecodable", [])
    cl = _clusters_zs(header, samples)
    if cl:
        return ("zs", cl)
    if mode == "zs":
        return ("undecodable", [])
    return ("raw", [(0, samples, sum(samples))])


# Time scales. The chip reads every channel once per 4000 bunch crossings
# and the bx clock is 40 MHz, i.e. one readout every 100 us. Inside that
# window the samples run at 10 MS/s, one every 0.1 us. If the bx clock or the
# ADC clock is ever changed from the PLL, these two numbers must change with
# them: they are the only thing turning indices into microseconds.
#
# Measured on the bench PLL (M=96, N=5 -> VCO 960 MHz; adc /96 = 10 MHz,
# bx /24 = 40 MHz), and cross-checked two ways: 1000 samples at 10 MHz and
# 4000 bx at 40 MHz both give 100 us.
US_PER_READOUT = 100.0
US_PER_SAMPLE = 0.1

CSV_HEADER = [
    "packet", "readout", "received_utc", "chip", "channel", "type", "type_num",
    "bx", "t_us_start",
    "format", "n_samples", "n_clusters", "t_start", "sum", "max_adc",
    "truncated", "heartbeat", "trigger_early", "fifo_full", "header_ok",
    "samples",
]

CSV_HEADER_LONG = ["packet", "readout", "chip", "channel", "bx",
                      "t", "t_us", "adc"]

CSV_HEADER_CLUSTERS = ["packet", "readout", "chip", "channel", "bx",
                         "cluster", "t_start", "t_us_start", "size",
                         "sum"]


def packet_rows(n, readout, header, samples, problem, mode, ahora=""):
    """Turn a packet already read into the rows of the three files.

    Returns (packet_row, cluster_rows, sample_rows), in the order of
    CSV_HEADER, CSV_HEADER_CLUSTERS and CSV_HEADER_LONG.

    It lives here, outside CsvWriter, because two places use it: the CSV dump
    and sampa_data.py, which reads the .bin straight into in-memory tables.
    With a single copy they cannot end up interpreting the same file
    differently.
    """
    t_us_readout = readout * US_PER_READOUT
    format, clusters = decode(header, samples, mode)

    body = []
    sum = 0
    for _t0, chunk, s_cl in clusters:
        sum += s_cl
        if chunk is not None:
            body.extend(chunk)
    t_start = clusters[0][0] if clusters else ""
    max_adc = max(body) if body else ""

    row = [
        n, readout, ahora, header.hadd, header.chanadd,
        TYPE_NAMES.get(header.type, "?"), header.type,
        header.bunchcrossing, round(t_us_readout, 4),
        format, len(body), len(clusters),
        t_start, sum if clusters else "", max_adc,
        1 if header.type in (0x1, 0x3) else 0,
        1 if header.type == 0x0 else 0,
        1 if header.type in (0x3, 0x6, 0x7) else 0,
        1 if header.fifo_full else 0,
        0 if problem else 1,
        " ".join(str(x) for x in body),
    ]

    fc = []
    for k, (t0, chunk, s_cl) in enumerate(clusters):
        fc.append([n, readout, header.hadd, header.chanadd,
                   header.bunchcrossing, k, t0,
                   round(t_us_readout + t0 * US_PER_SAMPLE, 4),
                   len(chunk) if chunk is not None else "", s_cl])

    fm = []
    for t0, chunk, _s in clusters:
        if chunk is None:
            continue
        for k, adc in enumerate(chunk):
            t = t0 + k
            fm.append([n, readout, header.hadd, header.chanadd,
                       header.bunchcrossing, t,
                       round(t_us_readout + t * US_PER_SAMPLE, 4), adc])

    return row, fc, fm


class CsvWriter(object):
    """Dump the packets to CSV, one per line.

    All the samples go into a single column, separated by spaces. That is
    deliberate: their number varies between 0 and ~1024 depending on the
    packet, so one column per sample would give a 1024-column table that is
    almost entirely empty. In pandas it opens with
    df["samples"].str.split() and that is it.

    With long=True a second file is written in long format (one row per
    sample), which is usually the most convenient one for analysis.

    Every file carries a "readout" column: a counter that goes up each time
    the chip dumps all 32 channels. That is what should be used as the time
    axis, NOT bx, which is a 20-bit counter and wraps every 26 ms. From it
    the microseconds are given already computed (t_us / t_us_start) so that
    whoever analyses the data need know nothing about bunch crossings or
    windows.
    """

    def __init__(self, prefix, long_fmt=False, clusters=False, mode="auto"):
        self.mode = mode
        self.path = prefix + "_packets.csv"
        self.f = open(self.path, "w")
        self.w = csv.writer(self.f)
        self.w.writerow(CSV_HEADER)
        self.fl = None
        self.wl = None
        self.path_long = None
        if long_fmt:
            self.path_long = prefix + "_samples.csv"
            self.fl = open(self.path_long, "w")
            self.wl = csv.writer(self.fl)
            self.wl.writerow(CSV_HEADER_LONG)
        self.fc = None
        self.wc = None
        self.path_clusters = None
        if clusters:
            self.path_clusters = prefix + "_clusters.csv"
            self.fc = open(self.path_clusters, "w")
            self.wc = csv.writer(self.fc)
            self.wc.writerow(CSV_HEADER_CLUSTERS)
        self.rows = 0
        self.filas_largo = 0
        self.filas_clusters = 0
        # The 32 packets of one readout arrive together and share the same
        # bx, so watching for a change is enough.
        self.readout = -1
        self._bx_ant = None

    def add(self, n, header, samples, problem):
        # utcnow() has been deprecated since Python 3.12: it returned a
        # naive object holding UTC time, which is exactly the ambiguity they
        # wanted to remove. The explicit equivalent appends "+00:00", which
        # is more honest for a column called received_utc.
        ahora = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if header.bunchcrossing != self._bx_ant:
            self.readout += 1
            self._bx_ant = header.bunchcrossing
        row, fc, fm = packet_rows(n, self.readout, header, samples,
                                        problem, self.mode, ahora)

        self.w.writerow(row)
        self.rows += 1

        if self.wc is not None:
            for f in fc:
                self.wc.writerow(f)
                self.filas_clusters += 1

        if self.wl is not None:
            for f in fm:
                self.wl.writerow(f)
                self.filas_largo += 1

        if self.rows % 500 == 0:
            self.f.flush()
            if self.fl is not None:
                self.fl.flush()
            if self.fc is not None:
                self.fc.flush()

    def close(self):
        self.f.close()
        if self.fl is not None:
            self.fl.close()
        if self.fc is not None:
            self.fc.close()
        print("")
        print("CSV written: {0}  ({1} packets)".format(self.path, self.rows))
        if self.path_long:
            print("CSV written: {0}  ({1} samples)".format(
                self.path_long, self.filas_largo))
        if self.path_clusters:
            print("CSV written: {0}  ({1} clusters)".format(
                self.path_clusters, self.filas_clusters))


def recv_exactly(sock, nbytes):
    """Read exactly nbytes. Returns None if the server closes."""
    buf = b""
    while len(buf) < nbytes:
        try:
            chunk = sock.recv(nbytes - len(buf))
        except socket.timeout:
            return None
        except socket.error as e:
            if e.errno == errno.EINTR:
                continue
            raise
        if not chunk:
            return None
        buf += chunk
    return buf


class FileSource(object):
    """Make a file look like a socket, to re-read a capture taken with nc
    on the board. Same decoding, without depending on the network."""

    def __init__(self, path):
        self.f = open(path, "rb")

    def recv(self, nbytes):
        return self.f.read(nbytes)

    def settimeout(self, _t):
        pass

    def close(self):
        self.f.close()


class TeeSource(object):
    """Wrap the source and save everything that arrives to disk.

    The resulting file is byte for byte what sampa_server sent, so it can be
    reprocessed with -f. It is the only lossless copy we keep: the CSV files
    already carry an interpretation on top (the compression mode, the
    unpacking of the 10-bit samples), and if that interpretation ever turned
    out to be wrong there would be no way back from them.

    It wraps recv() rather than the decoded packets so that the file also
    includes the headers and stays aligned with the stream.
    """

    def __init__(self, fuente, path):
        self.fuente = fuente
        self.path = path
        self.f = open(path, "wb")
        self.bytes = 0
        self._sin_vaciar = 0

    def recv(self, nbytes):
        datos = self.fuente.recv(nbytes)
        if datos:
            self.f.write(datos)
            self.bytes += len(datos)
            self._sin_vaciar += len(datos)
            # A long capture may end in a Ctrl-C or in a yanked cable, so we
            # do not leave whole megabytes sitting only in the buffer.
            if self._sin_vaciar >= 1 << 20:
                self.f.flush()
                self._sin_vaciar = 0
        return datos

    def settimeout(self, t):
        self.fuente.settimeout(t)

    def close(self):
        self.f.close()
        self.fuente.close()
        print("")
        print("raw saved: {0}  ({1} bytes)".format(self.path, self.bytes))
        print("  it can be reprocessed with:  "
              "python3 sampa_sniff.py -f {0} --csv PREFIJO".format(self.path))


class Stats(object):
    def __init__(self):
        self.packets = 0
        self.samples = 0
        self.bytes = 0
        self.by_type = collections.Counter()
        self.by_chip = collections.Counter()
        self.by_channel = collections.Counter()
        # Besides the count, how many of those packets carried samples. That
        # is what tells a disabled channel (0%) from one that is merely
        # truncated some of the time (~40%); from the CSV both look the same:
        # no samples.
        self.by_channel_data = collections.Counter()
        self.problems = collections.Counter()
        self.started = time.time()

    def add(self, header, nbytes, problem):
        self.packets += 1
        if not header.dropped:
            self.samples += header.len
        self.bytes += nbytes
        self.by_type[header.type] += 1
        self.by_chip[header.hadd] += 1
        self.by_channel[(header.hadd, header.chanadd)] += 1
        if header.len and not header.dropped:
            self.by_channel_data[header.chanadd] += 1
        if problem:
            self.problems[problem] += 1

    def report(self):
        dt = max(time.time() - self.started, 1e-9)
        print("")
        print("--- summary ----------------------------------------------")
        print("  packets      : {0}  ({1:.1f}/s)".format(self.packets,
                                                        self.packets / dt))
        print("  samples      : {0}".format(self.samples))
        print("  bytes        : {0}  ({1:.1f} kB/s)".format(
            self.bytes, self.bytes / dt / 1000.0))
        if self.by_type:
            print("  by type      :")
            for t, n in sorted(self.by_type.items()):
                print("      {0} {1:<24s} {2}".format(
                    t, TYPE_NAMES.get(t, "?"), n))
        if self.by_chip:
            print("  by chip      : " + ", ".join(
                "{0}={1}".format(c, n) for c, n in sorted(self.by_chip.items())))
        if self.by_channel:
            print("  channels seen: {0}".format(len(self.by_channel)))
            self._by_channel()
        if self.problems:
            print("  PROBLEMS     :")
            for msg, n in self.problems.most_common():
                print("      {0:<42s} {1}".format(msg, n))
        else:
            print("  problems     : none")
        print("---------------------------------------------------------")

    def _by_channel(self):
        """Percentage of packets carrying samples, channel by channel.

        Four lines, one per link, because the channels are spread across the
        links and that is how bandwidth is actually shared. A channel
        disabled in CHEN shows up here as 0: it still sends empty headers, so
        from the packet count alone it looks alive.
        """
        total = collections.Counter()
        for (_chip, ch), n in self.by_channel.items():
            total[ch] += n
        if not total:
            return
        print("  by channel   : % of packets carrying samples")
        vacios = []
        for link in range(4):
            chs = [link * 8 + i for i in range(8)]
            if not any(total.get(c) for c in chs):
                continue
            cells = []
            for c in chs:
                t = total.get(c, 0)
                if not t:
                    cells.append("  -")
                    continue
                pct = 100.0 * self.by_channel_data.get(c, 0) / t
                cells.append("{0:3.0f}".format(pct))
                if self.by_channel_data.get(c, 0) == 0:
                    vacios.append(c)
            print("      link {0}  ch{1:2d}-{2:2d}: {3}".format(
                link, chs[0], chs[-1], " ".join(cells)))
        if vacios:
            print("      not a single sample: {0}".format(
                " ".join(str(c) for c in vacios)))
            print("      (this is what a channel disabled in CHEN looks like)")


class MissingFile(Exception):
    """A file that ships with this program is missing, not an external
    dependency that needs installing. Kept separate so we can say so
    clearly."""


class Board(object):
    """Run daqstat on the board over ssh and cache the result.

    It uses no SSH library: it calls the system's 'ssh' binary, which
    Windows 10 and every Linux already ship. That keeps sampa_sniff a single
    file you can copy and run.

    The cache matters: every request from the page must not open a fresh SSH
    connection. With a few tabs open that would be dozens per second, and the
    board (an ARM running BusyBox) cannot take it.
    """

    def __init__(self, target, path="./daqstat", every=3.0, timeout=10.0):
        self.target = target
        self.path = path
        self.every = every
        self.timeout = timeout
        self.lock = threading.Lock()
        self.when = 0.0
        self.raw = ""
        self.error = "the board has not been asked yet"

    def _run(self):
        # BatchMode=yes: if a password were needed, fail at once instead of
        # waiting for a keyboard that is not there.
        cmd = ["ssh", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new",
               "-o", "ConnectTimeout=5",
               self.target, self.path]
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=self.timeout)
        except FileNotFoundError:
            return "", "cannot find the 'ssh' program on this machine"
        except subprocess.TimeoutExpired:
            return "", "the board did not answer in {0:.0f} s".format(self.timeout)
        except Exception as e:                      # pragma: no cover
            return "", "could not launch ssh: {0}".format(e)

        out = p.stdout.decode("utf-8", "replace")
        if p.returncode != 0 and not out.strip():
            err = p.stderr.decode("utf-8", "replace").strip()
            return "", err or "ssh returned {0}".format(p.returncode)
        return out, ""

    def text(self):
        """The last dump, refreshed at most every 'every' seconds."""
        with self.lock:
            if time.time() - self.when < self.every:
                return self.raw, self.error
            self.when = time.time()
        raw, error = self._run()
        with self.lock:
            self.raw, self.error = raw, error
            return self.raw, self.error


# One row of the link table: name, three yes/no flags and four counters.
# Both spellings of the flags are accepted so an older, Spanish-language
# daqstat on the board still parses.
_ROW = re.compile(r"^\s*(\d+|DAS)\s+(yes|si|NO)\s+(yes|si|NO)\s+(YES|SI|no)\s+"
                  r"(\d+)\s+(\d+|-)\s+(\d+)\s+(\d+)\s*$")
_YES = ("yes", "si", "YES", "SI")


def parse_daqstat(text):
    """Turn a daqstat dump into something the page can draw.

    Deliberately tolerant: the board may carry an older daqstat whose output
    differs (the "packets to acquire" line changed format, and older builds
    printed Spanish). Anything not understood is left out; the raw text is
    always sent along, so in the worst case you still see the dump as-is.
    """
    d = {"links": [], "notes": []}
    for line in text.splitlines():
        m = _ROW.match(line)
        if m:
            d["links"].append({
                "name": m.group(1), "enabled": m.group(2) in _YES,
                "sync": m.group(3) in _YES, "fifo": m.group(4) in _YES,
                "packets": int(m.group(5)),
                "syncloss": None if m.group(6) == "-" else int(m.group(6)),
                "dropped": int(m.group(7)), "trunc": int(m.group(8))})
            continue
        m = re.match(r"\s*(?:firmware version|version del firmware)\s*:\s*(\d+)", line)
        if m: d["firmware"] = int(m.group(1)); continue
        m = re.match(r"\s*(?:server version|version del servidor)\s*:\s*(\d+)", line)
        if m: d["server"] = int(m.group(1)); continue
        m = re.match(r"\s*(?:client connected|cliente conectado)\s*:\s*(YES|SI|NO)", line)
        if m: d["client"] = m.group(1) in _YES; continue
        m = re.match(r"\s*CNTRL_REG\s*:\s*0x([0-9A-Fa-f]+)", line)
        if m: d["cntrl"] = int(m.group(1), 16); continue
        m = re.match(r"\s*STATUS_REG\s*:\s*0x([0-9A-Fa-f]+)", line)
        if m: d["status"] = int(m.group(1), 16); continue

    # daqstat's own "what to look at" block: it is its own diagnosis and is
    # worth more than anything we could work out here.
    for marker in ("--- what to look at", "--- que mirar"):
        chunk = text.split(marker)
        if len(chunk) > 1:
            for line in chunk[1].splitlines()[1:]:
                if line.strip().startswith("---"):
                    break
                if line.strip():
                    d["notes"].append(line.strip())
            break
    if "cntrl" in d:
        d["to_acquire"] = d["cntrl"] >> 16
        d["links_enabled"] = d["cntrl"] & 0x7FF
        d["das"] = bool(d["cntrl"] & (1 << 11))
    return d


class Panel(object):
    """Serve the live view over HTTP, on a separate thread.

    The page asks for /data every 0.7 s, or opens a WebSocket on /live and is
    pushed a snapshot instead. Both paths return the same JSON, so the page
    works either way.

    The accumulator lives here and is fed by the receive loop; the HTTP
    threads only read it under a lock.
    """

    def __init__(self, port, mode, title, board=None):
        try:
            import sampa_view
        except ImportError:
            # The live view reuses the drawing code from sampa_view, which
            # in turn uses sampa_data. Without --web they are not needed, so
            # it is easy to copy only this file and hit this at the worst
            # possible moment.
            raise MissingFile(
                "--web also needs sampa_view.py and sampa_data.py,\n"
                "  in this same directory. Copy them next to sampa_sniff.py.\n"
                "  Without --web this program works on its own.")
        self.sampa_view = sampa_view
        self.board = board
        self.acc = sampa_view.Accumulator(mode, title)
        self.lock = threading.Lock()
        self.port = port
        self.stopping = False
        self.clients = 0
        panel = self

        class Manejador(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                path = self.path.split("?")[0].rstrip("/") or "/"
                if path == "/vivo":
                    panel.websocket(self)
                    return
                if path == "/":
                    body = panel.html().encode("utf-8")
                    type = "text/html; charset=utf-8"
                elif path == "/datos":
                    body = panel.json().encode("utf-8")
                    type = "application/json"
                elif path == "/daq":
                    body = panel.daq().encode("utf-8")
                    type = "application/json"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except socket.error:
                    pass          # the browser left mid-write; never mind

            def log_message(self, *_a):
                pass              # no line per request: there are thousands

        class Servidor(ThreadingHTTPServer):
            # With keep-alive the browser leaves connections open and closes
            # them whenever it likes (a reload, switching tabs, the polling
            # that becomes redundant once the WebSocket is up). The thread
            # waiting for the next request dies, and socketserver prints the
            # whole traceback. It is not a failure: drop it and move on.
            def handle_error(self, request, client_address):
                clase = sys.exc_info()[0]
                if issubclass(clase, (ConnectionError, socket.timeout)):
                    return
                ThreadingHTTPServer.handle_error(self, request, client_address)

        self.srv = Servidor(("", port), Manejador)
        self.srv.daemon_threads = True
        self.thread = threading.Thread(target=self.srv.serve_forever)
        self.thread.daemon = True

    def start(self):
        self.thread.start()
        print("live view: http://localhost:{0}/".format(self.port))
        print("  data goes over a WebSocket; if that fails, the page")
        print("  falls back to polling every 0.7 s and looks the same")
        print("")
        print("  If you are reading this over ssh, open a tunnel from your machine:")
        # 127.0.0.1 and not "localhost": that name is resolved by the remote
        # machine, and on Windows it usually comes out as ::1 first. This
        # server only listens on IPv4, so with the name the connection is
        # refused even when everything else is fine.
        print("      ssh -L {0}:127.0.0.1:{0} USER@THIS_MACHINE"
              .format(self.port))
        print("  then open http://localhost:{0}/ in your browser."
              .format(self.port))
        print("  The WebSocket goes through the tunnel too: it is just TCP.")
        print("  If it does not load, check the ssh terminal: it says why.")

    def add(self, n, readout, header, samples, problem, nbytes):
        with self.lock:
            self.acc.add(n, readout, header, samples, problem, nbytes)

    def daq(self):
        """Board status, for the DAQ section of the page."""
        if self.board is None:
            return json.dumps({"active": False})
        raw, error = self.board.text()
        d = {"active": True, "target": self.board.target,
             "raw": raw, "error": error}
        if raw:
            d.update(parse_daqstat(raw))
        return json.dumps(d)

    def json(self):
        # The snapshot is built inside the lock, but it is fast compared
        # with the socket write, which happens outside it.
        with self.lock:
            return json.dumps(self.acc.snapshot(), separators=(",", ":"))

    def html(self):
        return self.sampa_view.page(vivo=True, title=self.acc.title)

    # The protocol handshake: concatenate the client's key with this fixed
    # GUID (RFC 6455), hash with SHA-1 and return it base64-encoded.
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    @staticmethod
    def frame(datos):
        """Frame a text message. Server-to-client frames are unmasked; the
        length uses one, three or nine bytes depending on the size."""
        n = len(datos)
        cab = bytearray([0x81])
        if n < 126:
            cab.append(n)
        elif n < 65536:
            cab.append(126)
            cab += struct.pack("!H", n)
        else:
            cab.append(127)
            cab += struct.pack("!Q", n)
        return bytes(cab) + datos

    def websocket(self, h):
        clave = h.headers.get("Sec-WebSocket-Key")
        if not clave:
            h.send_error(400, "this endpoint is a WebSocket")
            return
        aceptar = base64.b64encode(hashlib.sha1(
            (clave + self.GUID).encode("ascii")).digest()).decode("ascii")
        h.send_response(101)
        h.send_header("Upgrade", "websocket")
        h.send_header("Connection", "Upgrade")
        h.send_header("Sec-WebSocket-Accept", aceptar)
        h.end_headers()

        self.clients += 1
        ultimo = -1
        ultimo_envio = 0.0
        try:
            while not self.stopping:
                with self.lock:
                    n = self.acc.packets
                    ahora = time.time()
                    # Solo se manda si hay algo nuevo. Cada 5 s se manda de
                    # anyway: that lets the page tell "no data arriving"
                    # from "the receiver died".
                    manda = (n != ultimo) or (ahora - ultimo_envio > 5.0)
                    foto = self.acc.snapshot() if manda else None
                if manda:
                    ultimo = n
                    ultimo_envio = ahora
                    # The JSON dump happens outside the lock: it is the most
                    # expensive part here and must not slow down the thread
                    # reading the socket.
                    h.wfile.write(self.frame(
                        json.dumps(foto, separators=(",", ":")).encode("utf-8")))
                    h.wfile.flush()
                if not self._keepalive(h):
                    break
                time.sleep(0.25)
        except (socket.error, OSError, ValueError):
            pass                  # the browser left; nothing to do
        finally:
            self.clients -= 1

    @staticmethod
    def _keepalive(h):
        """Drain whatever the client sends and report if it closed.

        Browsers send little, but ping frames and the close frame do arrive
        and would otherwise pile up in the socket buffer. A clean close comes
        in as an opcode 8 frame.
        """
        h.connection.settimeout(0.0)
        try:
            datos = h.connection.recv(4096)
            if not datos:
                return False
            return (datos[0] & 0x0F) != 0x8
        except socket.error:
            return True           # no habia nada que leer
        finally:
            try:
                h.connection.settimeout(None)
            except socket.error:
                pass

    def stop(self):
        self.stopping = True
        self.srv.shutdown()


def run(args):
    if args.file:
        print("Reading capture {0} ...".format(args.file))
        try:
            sock = FileSource(args.file)
        except IOError as e:
            print("  could not open it: {0}".format(e))
            return 1
        print("")
    else:
        print("Connecting to {0}:{1} ...".format(args.host, args.port))
        try:
            sock = socket.create_connection((args.host, args.port),
                                            timeout=10.0)
        except socket.gaierror as e:
            # This is not a network failure: the name could not even be
            # resolved. With a literal IP that cannot happen, so whatever came
            # in on the command line was not an IP.
            print("  could not resolve the host: {0}".format(e))
            print("")
            print("  The host given was: {0!r}".format(args.host))
            print("  With a literal IP this should never fail, so check the")
            print("  argument. Common mistakes:")
            print("    - the port glued to the host   10.0.163.205:1000")
            print("    - un usuario delante         root@10.0.163.205")
            print("    - un caracter colado al copiar y pegar")
            print("")
            print("  The correct form is host and port as separate arguments:")
            print("    python sampa_sniff.py 10.0.163.205 1000")
            return 1
        except socket.error as e:
            print("  could not connect: {0}".format(e))
            print("")
            print("  Check on the board:")
            print("    ps | grep sampa_server        <- it must be running")
            print("    ./sampa_server {0}              <- the port is mandatory"
                  .format(args.port))
            print("  And that no other client is connected (only one fits).")
            return 1
        # timeout 0 = no limit: the receiver waits indefinitely. That is what
        # live monitoring needs, where minutes can go by between bursts
        # without a single byte.
        sock.settimeout(args.timeout if args.timeout > 0 else None)
        print("Connected. Ctrl-C to stop.")
        print("")

    if args.save:
        try:
            sock = TeeSource(sock, args.save)
        except IOError as e:
            print("  could not create {0}: {1}".format(args.save, e))
            sock.close()
            return 1
        print("saving the raw stream to {0} ...".format(args.save))

    # Raw mode: no interpretation at all, just show what arrives
    if args.raw:
        data = recv_exactly(sock, args.raw * 4)
        if data is None:
            print("the server closed the connection without sending anything")
            return 1
        for i in range(0, len(data), 4):
            w = struct.unpack("<I", data[i:i + 4])[0]
            print("  palabra {0:4d}  0x{1:08X}  {2:032b}".format(i // 4, w, w))
        return 0

    panel = None
    if args.web:
        board = None
        if args.board is not None:
            # With no value, the board is the same machine the data comes
            # from. That is the normal case: sampa_server and daqstat run on
            # the same box.
            target = args.board or "root@{0}".format(args.host)
            board = Board(target, args.daqstat)
        try:
            panel = Panel(args.web, args.mode,
                          args.file or "{0}:{1}".format(args.host, args.port),
                          board)
        except MissingFile as e:
            print("")
            print("  {0}".format(e))
            sock.close()
            return 1
        except socket.error as e:
            print("  could not open port {0}: {1}".format(args.web, e))
            sock.close()
            return 1
        panel.start()

    stats = Stats()
    writer = None
    if args.csv:
        writer = CsvWriter(args.csv, args.csv_long,
                             args.csv_clusters, args.mode)
        print("writing {0}_packets.csv ...".format(args.csv))
    readout = -1
    bx_ant = None
    try:
        while args.count == 0 or stats.packets < args.count:
            head = recv_exactly(sock, 8)
            if head is None:
                print("")
                if args.timeout > 0:
                    print("the server closed the connection (or sends nothing: "
                          "{0}s timeout)".format(args.timeout))
                else:
                    # With no wait limit, a cut can only mean the other end
                    # closing: mentioning a timeout here was misleading.
                    print("sampa_server closed the connection")
                if panel is not None:
                    print("the live view is still up; Ctrl-C to quit")
                break
            w0, w1 = struct.unpack("<II", head)
            header = Header(w0, w1)

            payload = b""
            if header.len32:
                payload = recv_exactly(sock, header.len32 * 4)
                if payload is None:
                    print("conexion cortada a mitad de un packet")
                    break
            words = list(struct.unpack("<{0}I".format(header.len32), payload)) \
                if header.len32 else []

            problem = header.problem()
            stats.add(header, 8 + len(payload), problem)

            # The 32 packets of one readout arrive together and share bx.
            if header.bunchcrossing != bx_ant:
                readout += 1
                bx_ant = header.bunchcrossing
            if panel is not None:
                panel.add(stats.packets, readout, header,
                          unpack_samples(header, words), problem,
                          8 + len(payload))

            if args.chip is not None and header.hadd != args.chip:
                continue
            if args.channel is not None and header.chanadd != args.channel:
                continue
            if args.only_problems and not problem:
                continue

            if writer is not None:
                writer.add(stats.packets, header,
                             unpack_samples(header, words), problem)

            if not args.quiet:
                prefix = "!" if problem else " "
                print("{0} #{1:<6d} {2}".format(prefix, stats.packets,
                                                header.line()))
                if problem:
                    print("            ^ {0}".format(problem))
                if args.header:
                    print("            header 0x{0:013X}   w0=0x{1:08X} "
                          "w1=0x{2:08X}  hamming=0x{3:02X} hpar={4} dpar={5}"
                          .format(header.raw, w0, w1, header.hamming,
                                  header.hparity, header.dparity))
                if args.samples and header.len and not header.dropped:
                    samples = unpack_samples(header, words)
                    # Con supresion de ceros el payload no son samples a
                    # secas: va en clusters, cada uno precedido de su size
                    # y su marca de tiempo (SAMPA_analyzer.cpp, ~590).
                    # If the first pair adds up, say so instead of showing
                    # the cluster header as if it were two samples.
                    body, note = samples, ""
                    if len(samples) > 2 and samples[0] + 2 == header.len:
                        body = samples[2:]
                        note = " [cluster of {0} from t={1}]".format(
                            samples[0], samples[1])
                    shown = body[:args.samples]
                    print("            samples ({0}): {1}{2}{3}".format(
                        len(body),
                        " ".join(str(s) for s in shown),
                        " ..." if len(body) > len(shown) else "",
                        note))
    except KeyboardInterrupt:
        print("")
    finally:
        sock.close()
        if writer is not None:
            writer.close()
        if panel is not None:
            panel.stop()
        stats.report()
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Look at the packets sampa_server sends.",
        epilog="Example: python3 sampa_sniff.py 10.0.163.205 1000 --samples 12")
    p.add_argument("host", nargs="?", default="10.0.163.205",
                   help="IP of the board (default 10.0.163.205)")
    p.add_argument("port", nargs="?", type=int, default=1000,
                   help="sampa_server port (default 1000)")
    p.add_argument("-n", "--count", type=int, default=0,
                   help="stop after N packets (0 = no limit)")
    p.add_argument("-s", "--samples", type=int, nargs="?", const=16, default=0,
                   metavar="N", help="show the first N samples")
    p.add_argument("-H", "--header", action="store_true",
                   help="show the raw header")
    p.add_argument("--chip", type=int, help="filter by hadd (chip)")
    p.add_argument("--channel", type=int, help="filter by channel")
    p.add_argument("--only-problems", action="store_true",
                   help="only suspicious packets")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="no line per packet, only the final summary")
    p.add_argument("--raw", type=int, metavar="N",
                   help="do not interpret: dump the first N words and exit")
    p.add_argument("--csv", metavar="PREFIX",
                   help="write PREFIX_packets.csv, one packet per line")
    p.add_argument("--csv-long", action="store_true",
                   help="also PREFIX_samples.csv in long format (one row "
                        "per sample: packet,readout,chip,channel,bx,t,t_us,adc)")
    p.add_argument("--csv-clusters", action="store_true",
                   help="also PREFIX_clusters.csv (one signal chunk per "
                        "row: t_start, size, sum)")
    p.add_argument("--mode", default="auto",
                   choices=("auto", "zs", "raw", "sum", "huffman"),
                   help="how the payload is compressed; VACFG in the chip "
                        "decides. auto = zero suppression, falling back to "
                        "raw. huffman cannot be decoded: it is flagged and no "
                        "samples are invented")
    p.add_argument("--web", type=int, nargs="?", const=8080, metavar="PORT",
                   help="serve the live view at http://localhost:PORT "
                        "(default 8080) while data is being received")
    p.add_argument("--board", nargs="?", const="", metavar="USER@IP",
                   help="with --web, add the DAQ status section: runs daqstat "
                        "on the board over ssh. With no value it uses "
                        "root@<host>. --board is not used for the data, which "
                        "still comes in over port 1000")
    p.add_argument("--daqstat", default="./daqstat", metavar="PATH",
                   help="path to daqstat on the board (default ./daqstat, "
                        "i.e. /home/root/daqstat)")
    p.add_argument("--save", metavar="FILE",
                   help="also save the stream exactly as it arrives, "
                        "uninterpreted. This is the lossless copy and is much "
                        "smaller than the CSV files; reprocess it with -f")
    p.add_argument("-f", "--file", metavar="FILE",
                   help="read a capture from disk instead of the network "
                        "(e.g. the one 'nc' makes on the board)")
    p.add_argument("-t", "--timeout", type=float, default=None,
                   help="seconds to wait with no data. 0 = no limit, it keeps "
                        "listening until Ctrl-C (default 5, or 0 when --web "
                        "is used)")
    args = p.parse_args(argv)
    if args.timeout is None:
        # Vigilar en vivo no tiene sentido con un limite de tiempo: entre
        # tandas puede no llegar nada durante minutos.
        args.timeout = 0.0 if args.web else 5.0
    if args.save and args.file:
        # Copying the file onto itself would truncate it to zero, and even
        # with another name it adds nothing: the raw stream is the input.
        p.error("--save makes no sense with -f: the input file already "
                "is the raw stream")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
