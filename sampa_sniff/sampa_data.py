#!/usr/bin/env python3
"""sampa_data - open a .bin capture as if it were a CSV, without the CSV.

The idea is to keep on disk only the binary the board sends, which is the
lossless copy and by far the smallest one (4.7 MB of .bin become 123 MB of
long CSV), and to build the table in memory the moment somebody asks for it.

    import sampa_data as sd

    pk = sd.packets("run1.bin")       # 9180 rows, one per packet
    sm = sd.samples("run1.bin")       # one row per sample
    df = pk.df()                      # the same thing as a pandas DataFrame

The columns are exactly the ones the CSV files carry, so everything CSV.md
explains applies here too. The only one missing is "received_utc": that is
the time the PC received the packet, and the binary does not store it. It
said nothing about the physical instant of the measurement anyway; that is
what "readout" and "t_us" are for.

The long tables are big, so you can filter while reading and never build the
whole thing:

    sd.samples("run1.bin", channel=3)
    sd.samples("run1.bin", channel=3, readout=(0, 50))

It works without pandas too: the table can be walked row by row, a single
column pulled out, or the whole thing dumped to CSV.
"""

import csv
import io
import struct
import sys

from sampa_sniff import (Header, unpack_samples, packet_rows,
                         CSV_HEADER, CSV_HEADER_LONG,
                         CSV_HEADER_CLUSTERS)

# "received_utc" only exists for a live capture; see the docstring.
_COL_PAQUETES = [c for c in CSV_HEADER if c != "received_utc"]
_I_TIME = CSV_HEADER.index("received_utc")


class Table(object):
    """An in-memory table, stored column-wise.

    Column-wise rather than row-wise because that is what pandas wants, and
    because for 3.6 million samples the memory difference is large.
    """

    def __init__(self, columns):
        self.columns = list(columns)
        self.datos = dict((c, []) for c in self.columns)

    def _append(self, row):
        for c, v in zip(self.columns, row):
            self.datos[c].append(v)

    def __len__(self):
        return len(self.datos[self.columns[0]]) if self.columns else 0

    def __iter__(self):
        """Walk the table row by row, each row as a dict."""
        for i in range(len(self)):
            yield dict((c, self.datos[c][i]) for c in self.columns)

    def column(self, nombre):
        return self.datos[nombre]

    def df(self):
        """The same table as a pandas DataFrame."""
        try:
            import pandas as pd
        except ImportError:
            raise ImportError(
                "pandas is needed for this:  pip install pandas\n"
                "Without pandas the table still works: walk it with a "
                "for loop, pull one column with .column('adc'), or "
                "dump it with .csv('file.csv')")
        return pd.DataFrame(self.datos, columns=self.columns)

    def csv(self, path):
        """Dump the table to a CSV, in case somebody needs it on disk."""
        with io.open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(self.columns)
            for i in range(len(self)):
                w.writerow([self.datos[c][i] for c in self.columns])
        return path

    def __repr__(self):
        return "<Table {0} rows x {1} columns: {2}>".format(
            len(self), len(self.columns), ", ".join(self.columns))


def _walk(path, mode):
    """Yields (n, readout, header, samples, problem) from the .bin.

    The same walk sampa_sniff does over the socket, but across the whole
    file. The readout counter goes up when bx changes, exactly as it does
    there: the 32 packets of one readout arrive together and share it.
    """
    with open(path, "rb") as f:
        n = 0
        readout = -1
        bx_ant = None
        while True:
            head = f.read(8)
            if len(head) < 8:
                break
            w0, w1 = struct.unpack("<II", head)
            header = Header(w0, w1)
            payload = f.read(header.len32 * 4) if header.len32 else b""
            if len(payload) < header.len32 * 4:
                # Capture cut off mid-packet: drop it rather than invent
                # samples out of whatever arrived.
                break
            words = list(struct.unpack("<{0}I".format(header.len32), payload)) \
                if header.len32 else []
            n += 1
            if header.bunchcrossing != bx_ant:
                readout += 1
                bx_ant = header.bunchcrossing
            yield n, readout, header, unpack_samples(header, words), \
                header.problem()


def _matches(header, readout, channel, chip, rango):
    if channel is not None and header.chanadd != channel:
        return False
    if chip is not None and header.hadd != chip:
        return False
    if rango is not None and not (rango[0] <= readout <= rango[1]):
        return False
    return True


def _read(path, which, mode, channel, chip, readout):
    columns = {"packets": _COL_PAQUETES,
                "clusters": CSV_HEADER_CLUSTERS,
                "samples": CSV_HEADER_LONG}[which]
    t = Table(columns)
    for n, rd, header, samples, problem in _walk(path, mode):
        if not _matches(header, rd, channel, chip, readout):
            continue
        row, fc, fm = packet_rows(n, rd, header, samples, problem,
                                        mode)
        if which == "packets":
            t._append(row[:_I_TIME] + row[_I_TIME + 1:])
        elif which == "clusters":
            for f in fc:
                t._append(f)
        else:
            for f in fm:
                t._append(f)
    return t


def packets(path, mode="auto", channel=None, chip=None, readout=None):
    """One row per packet. The small table, and the one good for almost everything."""
    return _read(path, "packets", mode, channel, chip, readout)


def samples(path, mode="auto", channel=None, chip=None, readout=None):
    """One row per sample. This is the big one: filter by channel."""
    return _read(path, "samples", mode, channel, chip, readout)


def clusters(path, mode="auto", channel=None, chip=None, readout=None):
    """One row per signal chunk."""
    return _read(path, "clusters", mode, channel, chip, readout)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 0
    path = argv[0]
    for which, f in (("packets", packets), ("clusters", clusters)):
        t = f(path)
        print("{0:>9s}: {1}".format(which, t))
    return 0


if __name__ == "__main__":
    sys.exit(main())
