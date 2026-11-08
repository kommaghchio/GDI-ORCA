import argparse
import os
import re
import shutil
import subprocess
import sys
import traceback
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = os.path.join(SCRIPT_DIR, "lcsc.txt")
DEFAULT_OUTPUT = os.path.join(SCRIPT_DIR, "lib", "lcsc")
LOG_PATH = os.path.join(SCRIPT_DIR, "lcsc.log")


class _Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
            stream.flush()

    def flush(self):
        for stream in self.streams:
            stream.flush()


def protected_folder_message(path):
    """Windows ransomware protection blocks new files in Documents and reports a missing file."""
    documents = os.path.abspath(os.path.join(os.path.expanduser("~"), "Documents"))
    target = os.path.abspath(path)
    try:
        inside_documents = os.path.commonpath([target, documents]) == documents
    except ValueError:
        inside_documents = False
    parent = os.path.dirname(target)
    blocked = isinstance(path, str) and inside_documents and os.path.isdir(parent)
    if not blocked:
        return None
    return (
        "Windows Security blocked Python from changing this folder "
        "(Controlled folder access).\n"
        "Allow this app through ransomware protection:\n"
        f"  {sys.executable}\n"
        "Windows Security > Virus & threat protection > Ransomware protection > "
        "Allow an app through Controlled folder access."
    )


_hint_printed = False


def report_create_error(prefix, path, exc):
    global _hint_printed
    print(f"{prefix}: {path}")
    print(exc)
    if _hint_printed or getattr(exc, "winerror", None) not in (2, 5):
        return
    hint = protected_folder_message(path)
    if hint:
        print(hint)
        _hint_printed = True


def pause_if_console():
    """Keep a double-clicked console open long enough to read the error."""
    if not sys.stdin or not sys.stdin.isatty():
        return
    print()
    if log_file is not None:
        print(f"Output was also saved to {LOG_PATH}")
    print("Press Enter to close...")
    try:
        input()
    except EOFError:
        pass


def run_easyeda2kicad_from_file(input_file, output_dir=DEFAULT_OUTPUT, python_exec=None):
    input_file = os.path.expanduser(input_file)
    output_dir = os.path.expanduser(output_dir)
    python_exec = python_exec or sys.executable

    if not os.path.isfile(input_file):
        print(f"Error: File not found: {input_file}")
        return 2

    # If a simple name was provided, check PATH; if an absolute path, check that file exists.
    found = shutil.which(python_exec) if os.path.basename(python_exec) == python_exec else os.path.exists(python_exec)
    if not found:
        print(f"Warning: Python executable '{python_exec}' not found in PATH or as given path. Trying anyway.")

    # Pass a library prefix, not an existing directory. easyeda2kicad names the
    # KiCad library from the filename stem, so ".../lib/lcsc" becomes library "lcsc".
    # Creating that path as a folder forces the library name "easyeda2kicad".
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_dir)), exist_ok=True)
    except OSError as e:
        report_create_error("Error: Could not create output folder", output_dir, e)
        return 4

    with open(input_file, "r", encoding="utf-8") as f:
        # "C1234 FootprintName" — the name is optional. Blank lines and # comments are ignored.
        parts = []
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lcsc_id, _, footprint_name = line.partition(" ")
            parts.append((lcsc_id, footprint_name.strip() or None))

    if not parts:
        print("No LCSC IDs found in input file.")
        return 0

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    failed = False

    for idx, (lcsc_id, footprint_name) in enumerate(parts, start=1):
        cmd = [
            python_exec,
            "-m", "easyeda2kicad",
            "--full",
            "--overwrite",
            f"--lcsc_id={lcsc_id}",
            f"--output={output_dir}",
        ]
        print(f"[{idx}/{len(parts)}] Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
            )
        except FileNotFoundError as e:
            print(f"Executable not found: {e}")
            return 3

        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(result.stderr, end="" if result.stderr.endswith("\n") else "\n")
        if result.returncode != 0:
            print(f"Error processing {lcsc_id}: easyeda2kicad exited with code {result.returncode}")
            failed = True
            continue
        if footprint_name:
            apply_footprint_name(
                output_dir,
                f"{result.stdout or ''}\n{result.stderr or ''}",
                footprint_name,
            )

    if failed:
        return 1

    print("All commands completed.")
    return 0


def apply_footprint_name(output_prefix, stdout, new_name):
    """Rename the footprint easyeda2kicad just wrote, and the symbol link to it."""
    match = re.search(r"Footprint name:\s*(\S+)", stdout)
    if not match:
        print(f"Could not rename footprint to {new_name}: name not found in easyeda2kicad output.")
        return
    old_name = match.group(1)
    if old_name == new_name:
        return

    pretty = output_prefix + ".pretty"
    src = os.path.join(pretty, old_name + ".kicad_mod")
    dst = os.path.join(pretty, new_name + ".kicad_mod")
    with open(src, "r", encoding="utf-8") as f:
        footprint = f.read()
    footprint = footprint.replace(f"(module easyeda2kicad:{old_name}", f"(module lcsc:{new_name}", 1)
    footprint = footprint.replace(f'(footprint "{old_name}"', f'(footprint "{new_name}"', 1)
    footprint = footprint.replace(f"(fp_text value {old_name} ", f"(fp_text value {new_name} ", 1)
    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write(footprint)
    if os.path.abspath(src) != os.path.abspath(dst):
        os.remove(src)

    sym_path = output_prefix + ".kicad_sym"
    with open(sym_path, "r", encoding="utf-8") as f:
        symbols = f.read()
    symbols = symbols.replace(f'"lcsc:{old_name}"', f'"lcsc:{new_name}"')
    symbols = symbols.replace(f'"easyeda2kicad:{old_name}"', f'"lcsc:{new_name}"')
    with open(sym_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(symbols)
    print(f"Renamed footprint {old_name} -> {new_name}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run easyeda2kicad for a list of LCSC IDs.")
    parser.add_argument("input_file", nargs="?", default=DEFAULT_INPUT, help="Path to file with one LCSC ID per line")
    parser.add_argument("output_dir", nargs="?", default=DEFAULT_OUTPUT, help="Output library path without an extension")
    parser.add_argument("--python", dest="python_exec", default=None,
                        help="Python executable to use (default: the interpreter running this script)")
    args = parser.parse_args(argv)

    return run_easyeda2kicad_from_file(args.input_file, args.output_dir, args.python_exec)


if __name__ == "__main__":
    log_file = None
    code = 1
    try:
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        try:
            log_file = open(LOG_PATH, "a", encoding="utf-8", errors="replace")
            log_file.write(f"\n----- {datetime.now().isoformat(timespec='seconds')} -----\n")
            log_file.flush()
            sys.stdout = _Tee(sys.stdout, log_file)
            sys.stderr = _Tee(sys.stderr, log_file)
        except OSError as e:
            report_create_error("Warning: could not write log", LOG_PATH, e)
        code = main()
    except Exception:
        traceback.print_exc()
    finally:
        pause_if_console()
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        if log_file is not None:
            log_file.close()
    sys.exit(code if isinstance(code, int) else 1)
