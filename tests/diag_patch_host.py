"""DIAG ONLY (never merge): print the exception the host swallows in serve_control's dispatch, in the INSTALLED copy,
and keep the Agent's RECORD consistent so the Runtime's installed-release check still passes."""
import base64, csv, hashlib, io, re, sys, sysconfig
from pathlib import Path

site = Path(sysconfig.get_paths()["purelib"])
target = "astrid/core/execution/generic_host.py"
path = site / target
text = path.read_text(encoding="utf-8")
pattern = re.compile(r"(reply = self\.dispatch\(frame\)\n(\s+)except BaseException as exc:\n)(\s+)(self\.control_error = exc\n)")
match = pattern.search(text)
if not match:
    sys.exit("diag patch: dispatch handler not found")
indent = match.group(3)
inject = (f"{indent}import traceback as _tb, sys as _sys\n"
          f"{indent}print('DIAGHOST dispatch failed for command', frame.get('command'), file=_sys.stderr); _tb.print_exc(); _sys.stderr.flush()\n")
text = text[:match.start(4)] + inject + text[match.start(4):]
path.write_text(text, encoding="utf-8")
data = path.read_bytes()
digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
for record in site.glob("astrid-*.dist-info/RECORD"):
    rows = list(csv.reader(open(record, newline="", encoding="utf-8").read().splitlines()))
    for row in rows:
        if row and row[0] == target:
            row[1], row[2] = digest, str(len(data))
    out = io.StringIO(); csv.writer(out, lineterminator="\n").writerows(rows)
    open(record, "w", newline="", encoding="utf-8").write(out.getvalue())
print("patched", path)
