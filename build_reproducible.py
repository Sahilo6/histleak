"""Builds dist/histleak.pyz with byte-identical output across runs.

`python3 -m zipapp` writes each entry's mtime as the moment you ran it, so
rebuilding a minute later changes every entry's timestamp bytes even though
the source didn't change. This writes the same zip by hand through
`zipfile`, pinning every `ZipInfo.date_time` to a fixed value, so the
output only changes when `histleak.py` does.

Standard library only: zipfile, pathlib, stat.
"""

import pathlib
import stat
import zipfile

FIXED_DATE_TIME = (2026, 1, 1, 0, 0, 0)
OUT = pathlib.Path("dist/histleak.pyz")
SOURCE = pathlib.Path("histleak.py")


def build() -> None:
    OUT.parent.mkdir(exist_ok=True)
    if OUT.exists():
        OUT.unlink()

    with open(OUT, "wb") as f:
        f.write(b"#!/usr/bin/env python3\n")
        with zipfile.ZipFile(f, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            main_src = f"import histleak\nimport sys\nsys.exit(histleak.main())\n"
            for name, data in (
                ("__main__.py", main_src.encode()),
                ("histleak.py", SOURCE.read_bytes()),
            ):
                info = zipfile.ZipInfo(name, date_time=FIXED_DATE_TIME)
                info.external_attr = (0o644 << 16)
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, data)

    OUT.chmod(OUT.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    build()
