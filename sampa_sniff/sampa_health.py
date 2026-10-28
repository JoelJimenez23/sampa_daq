#!/usr/bin/env python3
"""sampa_health - what the fault supervisor (sampa_fdir) tells the operator.

sampa_fdir runs on the board and writes three files in its state directory:

    status.json   what it sees right now (rewritten twice a second)
    events.jsonl  one JSON line per notable event (problem seen, repair
                  started, repair ended, server restarted, ...)
    fdir.log      the full, technical journal

This module reads them and turns them into two views:

  * a SIMPLE one for people who do not care how the system works: a colour,
    one sentence for the problem, one for the action taken, and whether the
    data may be affected;
  * the full journal, streamed live, for the technician.

The wording lives here and only here: the supervisor reports stable codes
(flag names, event kinds) and this file decides what to tell a human.

The files are read through the same ssh path as the daqstat panel (Board in
sampa_sniff.py), or straight from a directory (--fdir-dir): that is how the
page is tried without a board, and how it works if sampa_sniff runs on the
board itself. No SSH library, standard library only.
"""

import json
import os
import shlex
import threading
import time

# ---- levels ----------------------------------------------------------------
# What the page colours by. Ordered by how much a person should care.
OK = "ok"                    # green:  all normal
IDLE = "idle"                # grey:   supervisor waiting for the system to start
WORKING = "working"          # amber:  it is repairing something, wait
ATTENTION = "attention"      # amber:  something happened that it cannot fix
DECISION = "decision"        # red:    stopped, a person has to act
UNKNOWN = "unknown"          # grey:   cannot tell (no supervisor, no contact)

SEVERITY = {OK: 0, IDLE: 0, UNKNOWN: 1, WORKING: 2, ATTENTION: 3, DECISION: 4}

# ---- the wording -----------------------------------------------------------
# flag name -> (problem, what the system does about it, data affected?)
# "data" is True when data was or may have been lost while it lasted.

FAULTS = {
    "SYNC_LOSS": ("A data link lost synchronisation.",
                  "Restoring it automatically.", True),
    "STALL": ("Data stopped flowing on a link.",
              "Restarting the acquisition automatically.", True),
    "ENABLE_DRIFT": ("A data link was switched off unexpectedly.",
                     "Switching it back on automatically.", True),
    "HAMMING": ("The chip is sending damaged packet headers.",
                "Resetting the chip automatically.", True),
    "CONFIG_DRIFT": ("The chip's configuration changed by itself.",
                     "Writing the configuration again automatically.", True),
    "FATAL_BUS": ("The board's FPGA bridge does not respond.",
                  "Everything was stopped to protect the hardware.", True),
    "FATAL_I2C": ("The chip does not answer on its control bus "
                  "(is its power supply on?).",
                  "Everything was stopped until the chip answers.", True),
}

WARNINGS = {
    "overload": ("There is more data than the system can carry.",
                 "Nothing can be repaired automatically. Reduce the data: "
                 "enable zero suppression or use fewer channels.", True),
    "sync_blip": ("A data link lost synchronisation briefly and recovered "
                  "by itself.", "No action was needed.", True),
    "fifo_flag": ("The FPGA's buffer overflowed and some packets were "
                  "dropped.", "Nothing can be repaired automatically. "
                  "Reduce the data rate.", True),
    "truncated": ("The chip is cutting packets short because it is "
                  "overloaded.", "Nothing can be repaired automatically. "
                  "Reduce the data rate.", True),
    "bx_gap": ("Some packets are missing from the data stream.",
               "Reported only: lost data cannot be recovered.", True),
    "bad_header": ("Packets with an invalid header were received.",
                   "Reported only.", True),
    "link_errors": ("The chip is correcting errors on a data link; the "
                    "cable or connector may be degrading.",
                    "Reported only. The data is intact for now: ask a "
                    "technician to check the cables.", False),
    "tcp_client": ("The program receiving the data is not getting it.",
                   "Reported only.", True),
}

# status.json "tcp.problem" -> more specific wording for tcp_client
TCP_PROBLEMS = {
    "second_client": ("A second viewer tried to connect while another one "
                      "was already connected, so it receives nothing.",
                      "The data server is restarted so the newest viewer "
                      "gets the data. Start the viewer again.", True),
    "client_not_reading": ("The program receiving the data is too slow and "
                           "cannot keep up.",
                           "Nothing can be repaired automatically. Data is "
                           "being lost while it lasts: close other programs "
                           "on that computer or record less data.", True),
    "stale_client_bit": ("The board believes a viewer is connected but none "
                         "is.", "Reported only.", False),
}

LEVELS = {
    "REPAIR": ("Fixing a problem.", False),
    "RESET_SOFT": ("Resetting the chip.", True),
    "RESET_HARD": ("Resetting the chip completely.", True),
}

# stop_reason substrings -> wording; checked in order
STOP_REASONS = (
    ("i2c", "The chip does not answer on its control bus "
            "(is its power supply on?)."),
    ("bus error", "The board's FPGA bridge does not respond."),
    ("ladder exhausted", "Automatic repair failed several times in a row."),
    ("budget", "Automatic repair failed several times in a row."),
    ("configuration", "The chip's configuration could not be restored."),
)

# bit values of status.json "last_flags" (fdir_types.h)
FLAG_BITS = (
    (1 << 0, "SYNC_LOSS"), (1 << 1, "STALL"), (1 << 2, "ENABLE_DRIFT"),
    (1 << 3, "HAMMING"), (1 << 4, "CONFIG_DRIFT"),
    (1 << 8, "overload"), (1 << 9, "sync_blip"), (1 << 10, "fifo_flag"),
    (1 << 11, "truncated"), (1 << 12, "bx_gap"), (1 << 13, "bad_header"),
    (1 << 14, "link_errors"), (1 << 15, "tcp_client"),
    (1 << 16, "FATAL_BUS"), (1 << 17, "FATAL_I2C"),
)

# a supervisor that has not written its heartbeat for this long is not there
STALE_S = 15


def flag_names(flags):
    return [name for bit, name in FLAG_BITS if flags & bit]


def _entry(name, status=None):
    """(problem, action, data) for a flag name; None if unknown."""
    if name == "tcp_client" and status:
        p = (status.get("tcp") or {}).get("problem")
        if p in TCP_PROBLEMS:
            return TCP_PROBLEMS[p]
    if name in FAULTS:
        return FAULTS[name]
    return WARNINGS.get(name)


def stop_text(reason):
    low = (reason or "").lower()
    for key, text in STOP_REASONS:
        if key in low:
            return text
    return "The system stopped itself to protect the hardware."


def _ago(seconds):
    if seconds is None:
        return ""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "{0} s ago".format(seconds)
    if seconds < 3600:
        return "{0} min ago".format(seconds // 60)
    return "{0} h ago".format(seconds // 3600)


# ---- the events (history) --------------------------------------------------

def describe_event(ev):
    """One event of events.jsonl -> (level, problem, action) or None.

    None means the event is not worth showing to a person (plumbing)."""
    kind, det = ev.get("kind"), ev.get("detail", "")
    if kind == "fault_seen":
        names = [n for n in det.split(",") if n]
        known = [FAULTS[n] for n in names if n in FAULTS]
        if not known:
            return None
        return (WORKING, " ".join(k[0] for k in known),
                " ".join(k[1] for k in known))
    if kind == "recovery_begin":
        text, reset = LEVELS.get(det, ("Fixing a problem.", False))
        return (WORKING, "A problem was detected.",
                text + (" Data is interrupted until it ends." if reset else ""))
    if kind == "recovery_end":
        if det == "ok":
            return (OK, "The problem was fixed.", "Normal operation resumed.")
        return (WORKING, "A repair attempt did not work.",
                "Trying a stronger repair.")
    if kind == "stopped":
        return (DECISION, stop_text(det), "Everything was stopped. A technician "
                "must check the system.")
    if kind == "rearmed":
        return (OK, "The system was restarted by an operator.",
                "Monitoring again.")
    if kind == "server_restart":
        if det == "begin":
            return (WORKING, "Another viewer was waiting for data.",
                    "Restarting the data server.")
        if det == "ok":
            return (OK, "The data server was restarted.",
                    "Start the viewer again.")
        return (ATTENTION, "The data server could not be restarted.",
                "A technician must restart it.")
    if kind == "warn_raised":
        e = WARNINGS.get(det)
        return (ATTENTION, e[0], e[1]) if e else None
    if kind == "warn_cleared":
        e = WARNINGS.get(det)
        return (OK, "Resolved: " + e[0], "") if e else None
    if kind == "bringup_failed":
        return (ATTENTION, "Some data links did not synchronize.",
                "Automatic attempts did not work. Check the cables and the "
                "SAMPA supply.")
    if kind == "armed":
        return (OK, "Monitoring started.", "")
    return None


def history(events, board_now=None, limit=8):
    out = []
    for ev in events:
        d = describe_event(ev)
        if not d:
            continue
        level, problem, action = d
        age = None
        if board_now and ev.get("epoch_ms"):
            age = board_now - ev["epoch_ms"] / 1000.0
        out.append({"level": level, "problem": problem, "action": action,
                    "ago": _ago(age), "age": age, "kind": ev.get("kind"),
                    "detail": ev.get("detail", "")})
    return out[-limit:][::-1]            # newest first


# ---- the summary -----------------------------------------------------------

def summarize(status, board_now, events=(), latched=False, error=""):
    """The simple view: what is going on, in one place.

    status     status.json as a dict, or None
    board_now  the board's own clock, in seconds (its clock may be wrong, but
               it is compared with timestamps from that same clock)
    """
    out = {"active": True, "level": UNKNOWN, "headline": "", "problem": "",
           "action": "", "data": None, "since": "", "facts": [],
           "history": history(events, board_now), "decision": None,
           "clock_set": True}

    if not status:
        out["headline"] = "Fault monitor not reachable"
        out["problem"] = (error or "The fault monitor has not written its "
                          "status yet.")
        out["action"] = ("Ask a technician to start it on the board "
                         "(./run_fdir.sh start).")
        return out

    hb = status.get("heartbeat_epoch")
    out["clock_set"] = bool(status.get("clock_set", True))
    if hb is not None and board_now is not None and board_now - hb > STALE_S:
        out["headline"] = "Fault monitor not running"
        out["problem"] = ("It stopped reporting {0}. The system is not being "
                          "watched.".format(_ago(board_now - hb)))
        out["action"] = "Ask a technician to start it again."
        return out

    state = status.get("state", "")
    flags = int(status.get("last_flags", 0) or 0)
    names = flag_names(flags)
    entries = [(n, _entry(n, status)) for n in names]
    entries = [(n, e) for n, e in entries if e]
    out["facts"] = [
        ("state", state), ("flags", ",".join(names) or "none"),
        ("actions", "enabled" if status.get("actions_enabled") else
         "observe only"),
    ]

    if state == "STOPPED" or latched:
        out["level"] = DECISION
        out["headline"] = "Acquisition stopped"
        out["problem"] = stop_text(status.get("stop_reason", ""))
        out["action"] = ("Everything was stopped to protect the hardware. "
                         "A technician must check the system before it can "
                         "continue.")
        out["data"] = True
        out["decision"] = {"id": "rearm", "needs_technician": True,
                           "reason": status.get("stop_reason", "")}
        return out

    if state in ("REPAIR", "RESET_SOFT", "RESET_HARD"):
        text, reset = LEVELS[state]
        faults = [e for n, e in entries if n in FAULTS]
        out["level"] = WORKING
        out["headline"] = "Problem detected"
        out["problem"] = (" ".join(e[0] for e in faults) if faults
                          else "A problem was detected.")
        if reset or not faults:
            out["action"] = text + (" Data is interrupted until it ends."
                                    if reset else "")
        else:
            out["action"] = " ".join(e[1] for e in faults)
        out["data"] = True
        return out

    if status.get("standby") and status.get("bringup") == "reported":
        out["level"] = ATTENTION
        out["headline"] = "Some data links did not start"
        out["problem"] = ("Some of the data links did not synchronize"
                          + (" after several automatic attempts."
                             if status.get("actions_enabled") else "."))
        out["action"] = ("No data comes from them. Check the cables and the "
                         "SAMPA supply; the monitor keeps waiting and "
                         "nothing was stopped."
                         if status.get("actions_enabled") else
                         "Automatic repair is off. Ask a technician.")
        out["data"] = True
        return out

    if status.get("standby"):
        out["level"] = IDLE
        out["headline"] = "Waiting for the acquisition to start"
        out["problem"] = ""
        out["action"] = "The monitor is ready and will start watching by itself."
        return out

    if entries:
        faults = [e for n, e in entries if n in FAULTS]
        warns = [e for n, e in entries if n not in FAULTS]
        show = faults or warns
        out["level"] = WORKING if faults else ATTENTION
        out["headline"] = "Problem detected"
        out["problem"] = " ".join(e[0] for e in show)
        out["action"] = " ".join(e[1] for e in show)
        out["data"] = any(e[2] for e in show)
        return out

    out["level"] = OK
    out["headline"] = "All systems normal"
    out["action"] = "The fault monitor is watching."
    out["data"] = False
    return out


# ---- reading the files -----------------------------------------------------

def parse_events(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue                    # a half-written last line
        if isinstance(ev, dict):
            out.append(ev)
    return out


def split_lines(data, start):
    """Complete lines of 'data' (bytes). Returns (lines, bytes consumed).

    A last line without its newline is still being written: leave it for the
    next read rather than showing half of it."""
    cut = data.rfind(b"\n")
    if cut < 0:
        return [], 0
    chunk = data[:cut + 1]
    return chunk.decode("utf-8", "replace").splitlines(), len(chunk)


FIRST_READ = 20000          # bytes of journal shown when the page opens
MAX_READ = 200000


class Source(object):
    """Where the supervisor's files come from, with a small cache.

    board      a Board (sampa_sniff.py): files are read over ssh
    local_dir  a directory: files are read directly (tests, or sampa_sniff
               running on the board)
    """

    def __init__(self, board=None, local_dir=None,
                 state_dir="/home/root/sampa_fdir_state", every=2.0):
        self.board = board
        self.local_dir = local_dir
        self.state_dir = state_dir
        self.every = every
        self.lock = threading.Lock()
        self.when = 0.0
        self.cached = None

    @property
    def target(self):
        return self.local_dir or (self.board.target if self.board else "")

    # -- one poll: status + latch + recent events + the board's clock --------
    def snapshot(self):
        with self.lock:
            if self.cached and time.time() - self.when < self.every:
                return self.cached
            self.when = time.time()
        snap = self._read_snapshot()
        with self.lock:
            self.cached = snap
        return snap

    def _read_snapshot(self):
        if self.local_dir:
            return self._read_local()
        script = (
            "cd {d} 2>/dev/null || {{ echo @@NOSTATE; exit 0; }}; "
            "echo @@NOW $(date +%s); echo @@STATUS; cat status.json 2>/dev/null; "
            "printf '\\n@@LATCH\\n'; [ -e STOPPED ] && echo yes; "
            "printf '\\n@@EVENTS\\n'; tail -n 80 events.jsonl 2>/dev/null; "
            "printf '\\n@@END\\n'"
        ).format(d=shlex.quote(self.state_dir))
        out, err = self.board.run_cmd(script)
        if err and "@@" not in out:
            return {"error": err}
        return parse_snapshot(out)

    def _read_local(self):
        d = self.local_dir
        snap = {"now": time.time(), "status": None, "latched": False,
                "events": [], "error": ""}
        try:
            with open(os.path.join(d, "status.json")) as f:
                snap["status"] = json.load(f)
        except (OSError, ValueError):
            snap["error"] = "no status.json in " + d
        snap["latched"] = os.path.exists(os.path.join(d, "STOPPED"))
        try:
            with open(os.path.join(d, "events.jsonl"), "rb") as f:
                lines = f.read()[-60000:].decode("utf-8", "replace")
            snap["events"] = parse_events(lines)[-80:]
        except OSError:
            pass
        return snap

    # -- the journal, incrementally -----------------------------------------
    def journal(self, offset):
        """New complete lines of fdir.log after 'offset' (-1 = the tail).

        Returns (lines, next_offset, error). A smaller file than the offset
        means it was replaced: start again from its beginning."""
        if self.local_dir:
            return self._journal_local(offset)
        off = max(int(offset), -1)
        script = (
            "cd {d} 2>/dev/null || {{ echo @@NOSTATE; exit 0; }}; "
            "S=$(wc -c < fdir.log 2>/dev/null || echo 0); O={o}; "
            "if [ $O -lt 0 ]; then O=$((S-{first})); fi; "
            "if [ $O -lt 0 ]; then O=0; fi; "
            "if [ $O -gt $S ]; then O=0; fi; echo @@START $O; "
            "{{ tail -c +$((O+1)) fdir.log 2>/dev/null || "
            "dd if=fdir.log bs=1 skip=$O 2>/dev/null; }} | head -n 2000"
        ).format(d=shlex.quote(self.state_dir), o=off, first=FIRST_READ)
        out, err = self.board.run_cmd(script)
        return parse_journal(out, err)

    def _journal_local(self, offset):
        path = os.path.join(self.local_dir, "fdir.log")
        try:
            size = os.path.getsize(path)
        except OSError:
            return [], max(offset, 0), "no fdir.log in " + self.local_dir
        o = offset
        if o < 0:
            o = max(0, size - FIRST_READ)
        if o > size:
            o = 0
        with open(path, "rb") as f:
            f.seek(o)
            data = f.read(MAX_READ)
        lines, used = split_lines(data, o)
        return lines, o + used, ""


def parse_snapshot(out):
    """The marker-separated answer of the remote script -> a snapshot dict."""
    snap = {"now": None, "status": None, "latched": False, "events": [],
            "error": ""}
    if "@@NOSTATE" in out:
        snap["error"] = "the fault monitor's state directory does not exist"
        return snap
    section, body = None, {}
    for line in out.splitlines():
        if line.startswith("@@"):
            parts = line.split(None, 1)
            section = parts[0]
            body[section] = [parts[1]] if len(parts) > 1 else []
        elif section:
            body[section].append(line)
    try:
        snap["now"] = float(body.get("@@NOW", [""])[0])
    except (ValueError, IndexError):
        pass
    try:
        snap["status"] = json.loads("\n".join(body.get("@@STATUS", [])))
    except ValueError:
        snap["error"] = "status.json is not readable yet"
    snap["latched"] = "yes" in body.get("@@LATCH", [])
    snap["events"] = parse_events("\n".join(body.get("@@EVENTS", [])))
    return snap


def parse_journal(out, err=""):
    if "@@NOSTATE" in out:
        return [], 0, "the fault monitor's state directory does not exist"
    first, _, rest = out.partition("\n")
    if not first.startswith("@@START"):
        return [], 0, err or "unexpected answer from the board"
    try:
        start = int(first.split()[1])
    except (IndexError, ValueError):
        return [], 0, "unexpected answer from the board"
    data = rest.encode("utf-8", "replace")
    lines, used = split_lines(data, start)
    return lines, start + used, ""


def fdir_summary(source):
    """What the page asks for: the simple view, built from a fresh-enough
    snapshot. Never raises: an unreachable board is a normal state to show."""
    snap = source.snapshot()
    now = snap.get("now")
    if now is None and not snap.get("error"):
        now = time.time()
    s = summarize(snap.get("status"), now, snap.get("events", ()),
                  snap.get("latched", False), snap.get("error", ""))
    s["target"] = source.target
    return s


# ---- the technician's page -------------------------------------------------

JOURNAL_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fault monitor journal</title>
<style>
:root{--bg:#fbfbfa;--paper:#fff;--ink:#1a1a18;--soft:#6b6b66;--line:#e2e2dd;
      --bad:#a3322a;--warn:#9a6a1f;--ok:#2f7a4f;--trace:#2f6f8f}
:root:not([data-theme="light"]){}
@media (prefers-color-scheme:dark){:root{--bg:#16161a;--paper:#1e1e23;
      --ink:#e8e8e4;--soft:#9a9a94;--line:#33333a;--bad:#e0736a;--warn:#d9a24f;
      --ok:#6fc08f;--trace:#6fb3d2}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
     font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;
     display:flex;flex-direction:column;height:100vh}
header{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;
       gap:12px;align-items:center;flex-wrap:wrap}
h1{font-size:16px;margin:0;font-weight:600}
#state{font-size:13px;color:var(--soft);flex:1;min-width:200px}
button,label{font:inherit;font-size:13px}
button{background:var(--paper);color:var(--ink);border:1px solid var(--line);
       border-radius:6px;padding:4px 12px;cursor:pointer}
button:hover{border-color:var(--trace);color:var(--trace)}
#log{flex:1;overflow:auto;margin:0;padding:12px 16px;background:var(--paper);
     font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
     white-space:pre-wrap;word-break:break-word}
.l-alert{color:var(--bad)}.l-warn{color:var(--warn)}.l-ok{color:var(--ok)}
.l-dim{color:var(--soft)}
footer{padding:6px 16px;border-top:1px solid var(--line);color:var(--soft);
       font-size:12px}
</style></head><body>
<header><h1>Fault monitor journal</h1><span id="state">connecting&hellip;</span>
<label><input type="checkbox" id="follow" checked> follow</label>
<label><input type="checkbox" id="onlyimp"> only alerts</label>
<button id="pause">pause</button><button id="copy">copy</button></header>
<div id="log" role="log" aria-live="off"></div>
<footer>Timestamps are the board's own clock. A year of 1970 means its clock
was never set.</footer>
<script>
const log = document.getElementById("log"), st = document.getElementById("state");
let next = -1, paused = false, lines = [];
function cls(l) {
  if (/ALERT|STOPPED|FAULT|failed|FATAL/.test(l)) return "l-alert";
  if (/WARN|flags /.test(l)) return "l-warn";
  if (/CLEARED|recovered|restarted|supervising|rearmed/.test(l)) return "l-ok";
  return "";
}
function show() {
  const only = document.getElementById("onlyimp").checked;
  const frag = document.createDocumentFragment();
  for (const l of lines) {
    const c = cls(l);
    if (only && !c) continue;
    const d = document.createElement("div");
    if (c) d.className = c;
    d.textContent = l;
    frag.appendChild(d);
  }
  log.replaceChildren(frag);
  if (document.getElementById("follow").checked) log.scrollTop = log.scrollHeight;
}
async function poll() {
  if (paused) return;
  try {
    const r = await fetch("log?since=" + next, {cache: "no-store"});
    const d = await r.json();
    if (d.error) { st.textContent = d.error; return; }
    if (d.reset) lines = [];
    st.textContent = "live - " + lines.length + " lines";
    next = d.next;
    if (d.lines.length) {
      lines = lines.concat(d.lines).slice(-5000);
      show();
    }
  } catch (e) { st.textContent = "no answer from sampa_sniff"; }
}
document.getElementById("pause").onclick = e => {
  paused = !paused; e.target.textContent = paused ? "resume" : "pause";
};
document.getElementById("onlyimp").onchange = show;
document.getElementById("copy").onclick = () =>
  navigator.clipboard && navigator.clipboard.writeText(lines.join("\\n"));
poll(); setInterval(poll, 1500);
</script></body></html>
"""
