"""
LIVE CAPTURE - start the recording that src/live.py watches.

WHAT THIS FILE DOES
-------------------
It runs dumpcap (Wireshark's own recorder) on the wired adapter and tells it
to start a NEW capture file every 10 seconds in the session folder:

    dumpcap -i <adapter> -b duration:10 -w pcap/live/<session>/ring.pcapng -q

dumpcap names the files ring_00001_<time>.pcapng, ring_00002_<time>.pcapng,
and so on. src/live.py reads each one once the next exists. That is the whole
hand-over between the two programs: files in a folder. Nothing else is
shared, so either one can be restarted without the other noticing.

    Administrator PowerShell:   python -m src.live_capture --session live_session_01
    ordinary PowerShell:        python -m src.live --session live_session_01
    ordinary PowerShell:        streamlit run dashboard/app.py

WHY IT NEEDS AN ADMINISTRATOR TERMINAL, AND WHY IT CHECKS FIRST
---------------------------------------------------------------
Npcap (the driver dumpcap captures through) is installed on the lab laptop in
"Administrator only" mode. In an ordinary terminal dumpcap does not fail - it
waits forever, silently, for a permission prompt that never appears. That is
the worst possible behaviour in a demonstration, so this file checks BEFORE
starting dumpcap: if the terminal is not elevated and Npcap is admin-only, it
says so in plain words, prints the exact steps, and exits. It also prints the
Wireshark-GUI alternative, which writes exactly the same kind of files.

Only the capture needs elevation. The engine and the dashboard read finished
files and run as a normal user.

STOPPING
--------
Press Ctrl+C in this window. dumpcap receives the same Ctrl+C, finishes the
file it is writing and exits; then this file writes STOP into the session
folder, which tells the engine to read the last file and make its final pass.
STOP is written only if at least one capture file exists - if dumpcap never
managed to record anything, a STOP would only make a waiting engine give up.

While recording, a small marker file CAPTURING sits in the session folder.
It lets the engine tell "a capture of THIS session is running right now" apart
from "old files from an earlier session": if the engine is restarted in the
middle of a session, it joins the running capture and re-reads everything
from the first file, instead of refusing to start.

After stopping, the ring files are merged with mergecap into one file,
pcap/live/<session>.pcapng (beside the folder, not inside it, so the engine
never mistakes it for one more ring file). That single file is the forensic
record and can be played back later with  python -m src.live --replay.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not analyse anything; src/live.py does. It does not contact any
device or block anything. It does not know which device was attacked.

USAGE
-----
    python -m src.live_capture --list                       # the adapters dumpcap can see
    python -m src.live_capture --session live_session_01    # record until Ctrl+C
    python -m src.live_capture --session smoke --duration 60    # record one minute, then stop
    python -m src.live_capture --session s1 --interface 3       # pick an adapter by its --list number
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from src import live

ROOT = live.ROOT

# The wired adapter of the master laptop: every capture in this project so far
# was made on it (CLAUDE.md, "The lab"). Used when --interface is not given
# and dumpcap lists it; otherwise the operator must choose.
LAB_INTERFACE = r"\Device\NPF_{D913DCC8-4269-4A52-9617-38FEDDBB418A}"

# If dumpcap has written no file at all after this long, something is wrong
# (wrong adapter, no traffic, a permission prompt). Warn, do not abort.
STARTUP_WARNING_SECONDS = 25

# How long dumpcap gets to close its last file after Ctrl+C before it is
# ended forcibly. A forced end can cut the last packet in half; the engine
# reads such a file without error and keeps every complete packet.
STOP_GRACE_SECONDS = 10

# How often a progress line is printed while recording.
PROGRESS_SECONDS = 30

# How long `dumpcap -D` may take before we give up on it.
LIST_TIMEOUT_SECONDS = 20


# --------------------------------------------------------------------------
# Finding the tools
# --------------------------------------------------------------------------

def _find_wireshark_tool(name: str, explicit: str | None = None) -> str | None:
    """A Wireshark command-line tool: PATH first, then the standard installs."""
    if explicit:
        return explicit if Path(explicit).exists() else None
    found = shutil.which(name)
    if found:
        return found
    for candidate in (r"C:\Program Files\Wireshark\%s.exe" % name,
                      r"C:\Program Files (x86)\Wireshark\%s.exe" % name,
                      "/usr/bin/%s" % name, "/usr/local/bin/%s" % name,
                      "/opt/homebrew/bin/%s" % name):
        if Path(candidate).exists():
            return candidate
    return None


def find_dumpcap(explicit: str | None = None) -> str:
    """
    Locate dumpcap, the same way capture.find_tshark locates tshark: the
    Windows installer does not put Wireshark on PATH, so the install folder
    is checked too.
    """
    found = _find_wireshark_tool("dumpcap", explicit)
    if found:
        return found
    if explicit:
        raise FileNotFoundError("no dumpcap at %s" % explicit)
    raise FileNotFoundError(
        "dumpcap not found. It ships with Wireshark (https://www.wireshark.org).\n"
        "  If it is installed somewhere unusual, pass --dumpcap PATH.")


def find_mergecap(explicit: str | None = None) -> str | None:
    return _find_wireshark_tool("mergecap", explicit)


# --------------------------------------------------------------------------
# Is this terminal allowed to capture?
# --------------------------------------------------------------------------

def is_elevated() -> bool | None:
    """
    True if this terminal runs as Administrator (Windows) or root (elsewhere).
    None if it cannot be told, which is treated as "do not block".
    """
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


def npcap_admin_only() -> bool | None:
    """
    Is Npcap installed in "Administrator only" mode? Read from the registry
    value Npcap's installer writes. None if it cannot be told (not Windows,
    no Npcap, no permission to read the key).
    """
    if os.name != "nt":
        return None
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Services\npcap\Parameters")
        value, _ = winreg.QueryValueEx(key, "AdminOnly")
        return bool(value)
    except Exception:
        return None


def must_elevate(elevated: bool | None, admin_only: bool | None) -> bool:
    """
    Would dumpcap hang here? Only when we KNOW the terminal is not elevated
    and Npcap is not known to allow ordinary users. On a machine where either
    cannot be told (Linux, a different install) nothing is blocked.
    """
    return elevated is False and admin_only is not False


def elevation_message(session: str | None, listing: bool = False) -> str:
    """What to tell the operator, in plain words, when capture cannot work here."""
    session = session or "live_session_01"
    retry = "--list" if listing else "--session %s" % session
    folder = live.LIVE_DIR / session
    return "\n".join([
        "",
        "  This terminal is NOT running as Administrator, and on this laptop the",
        "  capture driver (Npcap) only works for Administrators. dumpcap would",
        "  wait here silently forever, so it has not been started.",
        "",
        "  Do this instead:",
        "    1. Start menu -> type  PowerShell  -> right-click -> Run as administrator",
        '    2. cd "%s"' % ROOT,
        "    3. .venv\\Scripts\\activate",
        "    4. python -m src.live_capture %s" % retry,
        "",
        "  Or use Wireshark's own window (it has the permission already):",
        "    Capture -> Options -> pick the wired adapter (Ethernet) ->",
        "    Output tab -> File: %s" % (folder / "ring.pcapng"),
        "    tick 'Create a new file automatically' -> after 10 seconds -> Start.",
        "",
    ])


# --------------------------------------------------------------------------
# Choosing the adapter
# --------------------------------------------------------------------------

_LIST_LINE = re.compile(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$")


def parse_interfaces(text: str) -> list:
    """
    Turn `dumpcap -D` output into rows. Each line looks like

        1. \\Device\\NPF_{D913DCC8-...} (Ethernet)

    i.e. a number, the device name, and a description in brackets.
    """
    rows = []
    for line in text.splitlines():
        match = _LIST_LINE.match(line)
        if match:
            rows.append({"number": int(match.group(1)), "device": match.group(2),
                         "description": (match.group(3) or "").strip()})
    return rows


def list_interfaces(dumpcap: str, timeout: float = LIST_TIMEOUT_SECONDS) -> list:
    """Ask dumpcap which adapters it can see."""
    try:
        result = subprocess.run([dumpcap, "-D"], capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "dumpcap -D gave no answer in %d s. That is what Npcap does to a terminal\n"
            "  that is not running as Administrator." % timeout)
    if result.returncode != 0:
        raise RuntimeError("dumpcap -D failed: %s" % (result.stderr.strip() or result.returncode))
    return parse_interfaces(result.stdout)


def choose_interface(interfaces: list, wanted: str | None = None,
                     default: str = LAB_INTERFACE) -> str:
    """
    Which adapter to record on.

    wanted may be the number from --list, the full device name, or a piece of
    the description ("Ethernet"). With no wanted, the lab's wired adapter is
    used if dumpcap lists it. Anything ambiguous or absent is an error that
    shows the list, rather than a guess: recording the wrong adapter gives a
    session that looks fine and contains nothing.
    """
    def table():
        return "\n".join("    %d. %s  %s" % (r["number"], r["device"], r["description"])
                         for r in interfaces) or "    (dumpcap listed no adapters)"

    if wanted is None:
        for row in interfaces:
            if row["device"].lower() == default.lower():
                return row["device"]
        raise ValueError("the lab's wired adapter is not in dumpcap's list - pick one with\n"
                         "  --interface <number>:\n%s" % table())

    wanted = str(wanted).strip()
    if wanted.isdigit():
        for row in interfaces:
            if row["number"] == int(wanted):
                return row["device"]
        raise ValueError("there is no adapter number %s:\n%s" % (wanted, table()))
    for row in interfaces:
        if row["device"].lower() == wanted.lower():
            return row["device"]
    matches = [r for r in interfaces if wanted.lower() in r["description"].lower()
               or wanted.lower() in r["device"].lower()]
    if len(matches) == 1:
        return matches[0]["device"]
    if not matches:
        raise ValueError("no adapter matches %r:\n%s" % (wanted, table()))
    raise ValueError("%r matches %d adapters - use the number instead:\n%s"
                     % (wanted, len(matches), table()))


# --------------------------------------------------------------------------
# Recording
# --------------------------------------------------------------------------

def capture_command(dumpcap: str, interface: str, folder: Path,
                    seconds: int = live.SEGMENT_SECONDS,
                    duration: float | None = None) -> list:
    """The dumpcap command line. -q: no per-packet counter on the console."""
    command = [dumpcap, "-i", interface, "-b", "duration:%d" % int(seconds),
               "-w", str(Path(folder) / "ring.pcapng"), "-q"]
    if duration:
        command += ["-a", "duration:%d" % int(duration)]
    return command


def prepare_capture_folder(folder: Path, force: bool = False) -> None:
    """
    A capture must start in a folder with no capture files in it.

    Old ring files mean an earlier session used this name; recording into the
    same folder would mix two sessions into one analysis. A CAPTURING marker
    means another capture is recording here right now (or one was killed
    without cleaning up). Either is refused unless --force, which clears the
    old files. A state.json from an engine already waiting is fine and kept.
    """
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    old = live.ring_files(folder)
    marker = folder / live.CAPTURE_MARKER
    stop = folder / live.STOP_FILE
    if not force:
        if marker.exists():
            raise FileExistsError(
                "%s says a capture is already recording into this folder.\n"
                "  If none is (it was closed without Ctrl+C), delete that file or pass --force."
                % marker)
        if old:
            raise FileExistsError(
                "%s already holds %d capture file(s) from an earlier session.\n"
                "  Pick a new --session name, or pass --force to delete them." % (folder, len(old)))
    for path in old + [p for p in (marker, stop) if p.exists()]:
        path.unlink()


def write_marker(folder: Path, interface: str, pid: int | None) -> Path:
    path = Path(folder) / live.CAPTURE_MARKER
    path.write_text(json.dumps({"interface": interface, "pid": pid,
                                "started_epoch": time.time()}), encoding="utf-8")
    return path


def finish_capture(folder: Path, reason: str) -> bool:
    """
    After dumpcap has exited: remove the CAPTURING marker, and write STOP if
    anything was recorded. Returns whether STOP was written.
    """
    folder = Path(folder)
    marker = folder / live.CAPTURE_MARKER
    if marker.exists():
        marker.unlink()
    if not live.ring_files(folder):
        return False
    (folder / live.STOP_FILE).write_text("stopped by live_capture: %s\n" % reason,
                                         encoding="utf-8")
    return True


def stop_process(process, grace: float = STOP_GRACE_SECONDS) -> int | None:
    """
    Wait for dumpcap to close its file and exit; end it forcibly if it does
    not within `grace` seconds. Ctrl+C reaches dumpcap directly (it shares
    this console), so usually it has already exited by the time this runs.
    """
    try:
        return process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait()


def merge_session(folder: Path, mergecap: str | None = None) -> Path | None:
    """
    Merge the ring files into pcap/live/<session>.pcapng, beside the folder.
    Returns the merged file, or None if there was nothing to merge or no
    mergecap. A failure here is reported, never fatal: the ring files
    themselves are the record and stay untouched.
    """
    folder = Path(folder)
    files = live.ring_files(folder)
    binary = find_mergecap(mergecap)
    if not files or not binary:
        return None
    out = folder.parent / ("%s.pcapng" % folder.name)
    result = subprocess.run([binary, "-w", str(out)] + [str(f) for f in files],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print("  mergecap failed (%s); the ring files are still in %s"
              % (result.stderr.strip()[:200], folder), file=sys.stderr)
        return None
    return out


def _size_text(paths) -> str:
    total = sum(p.stat().st_size for p in paths if p.exists())
    return "%.1f MB" % (total / 1e6) if total >= 1e5 else "%d KB" % (total // 1000)


def record(folder: Path, command: list, interface: str,
           startup_warning: float = STARTUP_WARNING_SECONDS,
           progress_every: float = PROGRESS_SECONDS,
           stop_grace: float = STOP_GRACE_SECONDS,
           merge: bool = True, mergecap: str | None = None,
           poll: float = 1.0) -> dict:
    """
    Run dumpcap until it exits by itself (--duration, or an error) or Ctrl+C.

    Returns what happened: files written, whether STOP was written, dumpcap's
    exit code, the merged file. `command` is passed in whole so the tests can
    run a stand-in recorder instead of dumpcap.
    """
    folder = Path(folder)
    started = time.monotonic()
    process = subprocess.Popen(command)
    write_marker(folder, interface, process.pid)
    reason = "dumpcap exited"
    warned = False
    last_progress = started
    try:
        while process.poll() is None:
            time.sleep(poll)
            elapsed = time.monotonic() - started
            files = live.ring_files(folder)
            if not files and not warned and elapsed > startup_warning:
                warned = True
                print("\n  WARNING: %d s and dumpcap has written no file yet.\n"
                      "  Wrong adapter? Is the laptop's network cable in? If it stays like\n"
                      "  this, press Ctrl+C and check  python -m src.live_capture --list\n"
                      % elapsed, file=sys.stderr)
            if files and time.monotonic() - last_progress >= progress_every:
                last_progress = time.monotonic()
                print("  recording  %3d s  %d files  %s" % (elapsed, len(files),
                                                            _size_text(files)))
    except KeyboardInterrupt:
        reason = "Ctrl+C"
        print("\n  Ctrl+C - letting dumpcap close its last file...")

    code = None
    try:
        code = stop_process(process, grace=stop_grace)
    except KeyboardInterrupt:          # a second Ctrl+C: end it now, still clean up
        process.kill()
        code = process.wait()
    finally:
        stopped = finish_capture(folder, reason)

    files = live.ring_files(folder)
    merged = merge_session(folder, mergecap) if merge and files else None
    return {"files": len(files), "stop_written": stopped, "exit_code": code,
            "reason": reason, "merged": merged, "seconds": time.monotonic() - started}


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Record the lab traffic as 10-second files for the live engine.")
    parser.add_argument("--session", help="session name, e.g. live_session_01 "
                                          "(the same name you give src.live)")
    parser.add_argument("--list", action="store_true",
                        help="print the adapters dumpcap can see, then exit")
    parser.add_argument("--interface", default=None,
                        help="adapter: number from --list, device name, or part of its "
                             "description (default: the lab's wired adapter)")
    parser.add_argument("--folder", default=None,
                        help="where the files go (default pcap/live/<session>)")
    parser.add_argument("--duration", type=float, default=None,
                        help="stop by itself after this many seconds")
    parser.add_argument("--no-merge", action="store_true",
                        help="do not merge the files into one .pcapng afterwards")
    parser.add_argument("--force", action="store_true",
                        help="delete capture files left in the folder by an earlier session")
    parser.add_argument("--skip-admin-check", action="store_true",
                        help="start dumpcap even if this terminal does not look elevated")
    parser.add_argument("--dumpcap", default=None)
    args = parser.parse_args(argv)

    if not args.list and not args.session:
        parser.error("give --session NAME (or --list)")

    if not args.skip_admin_check and must_elevate(is_elevated(), npcap_admin_only()):
        print(elevation_message(args.session, listing=args.list), file=sys.stderr)
        return 2

    try:
        dumpcap = find_dumpcap(args.dumpcap)
        interfaces = list_interfaces(dumpcap)
        if args.list:
            print()
            for row in interfaces:
                mark = "   <- the lab's wired adapter" \
                    if row["device"].lower() == LAB_INTERFACE.lower() else ""
                print("  %2d. %s  %s%s" % (row["number"], row["device"],
                                           row["description"], mark))
            print()
            return 0
        interface = choose_interface(interfaces, args.interface)
        folder = Path(args.folder) if args.folder else live.LIVE_DIR / args.session
        prepare_capture_folder(folder, force=args.force)
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError) as exc:
        print("\n  %s\n" % exc, file=sys.stderr)
        return 1

    description = next((r["description"] for r in interfaces if r["device"] == interface), "")
    print("\n  recording on   %s  %s" % (interface, description))
    print("  into           %s   (a new file every %d s)" % (folder, live.SEGMENT_SECONDS))
    if args.duration:
        print("  stops by itself after %d s" % args.duration)
    print("  stop with Ctrl+C in this window.\n")

    outcome = record(folder, capture_command(dumpcap, interface, folder,
                                             duration=args.duration),
                     interface, merge=not args.no_merge)

    print("\n  stopped (%s) after %d s: %d capture files in %s"
          % (outcome["reason"], outcome["seconds"], outcome["files"], folder))
    if outcome["stop_written"]:
        print("  STOP written - the engine will read the last file and finish.")
    else:
        print("  nothing was recorded, so no STOP was written (a waiting engine keeps waiting).")
    if outcome["merged"]:
        print("  merged copy:   %s" % outcome["merged"])
    if outcome["exit_code"] not in (0, None) and outcome["reason"] != "Ctrl+C":
        print("  dumpcap exit code %s - see its message above." % outcome["exit_code"],
              file=sys.stderr)
        return 1
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
