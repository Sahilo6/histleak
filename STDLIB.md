# STDLIB.md

Every package `histleak` would normally reach for, and what standard-library functionality
replaced it. All from Python 3's stdlib, no third-party runtime dependency anywhere.

| Normally | Instead | Where |
|---|---|---|
| `GitPython` / `pygit2` | `zlib` (inflate), `hashlib` (SHA-1 verification), `struct` (binary headers), `mmap` (random-access packfile reads) | `# --- object store ---`, `# --- packfile ---` |
| `gitleaks` / `trufflehog` | A hand-written rule table (`RULES`) with structural validators, plus a tuned Shannon-entropy detector built on `math.log2` and `collections.Counter` | `# --- detection ---` |
| `requests` / `httpx` | Not needed. `histleak` never makes a network call -- deliberately, since live key verification against provider APIs is out of scope (see README limitations) | n/a |
| `PyYAML` / `toml` | `json` for output; no config file format is needed since `.histleakignore` is a flat glob-per-line format parsed with a few lines of string splitting | `load_ignore_patterns()` |
| `click` / `typer` | `argparse`, subcommands via `add_subparsers` | `# --- cli ---` |
| `rich` / `colorama` | Plain text formatting; no ANSI color was worth the readability tradeoff in CI logs, so this substitution is "don't," documented rather than silently skipped | `print_text_report()` |
| `pytest` | `unittest`, stdlib's own test runner and assertion library | `test_histleak.py` |
| `regex` | `re`. Every detection pattern is expressible in stdlib `re`; none needed the extra features `regex` provides over the built-in engine | `# --- detection ---` |
| entropy-check libraries (e.g. `password-strength`) | `math.log2` + `collections.Counter` for Shannon entropy, from first principles | `shannon_entropy()` |
| `pyinstaller` / `shiv` | `zipapp`-style packaging done by hand through `zipfile`, with pinned `ZipInfo` timestamps for reproducibility (`python3 -m zipapp` alone is not reproducible: it stamps the current time) | `build_reproducible.py` |
| `pathspec` (gitignore-style matching) | `fnmatch`, sufficient for the flat glob patterns `.histleakignore` supports | `scan_repository()` |
| `tqdm` | Not used. A scan is a single pass with a known object count, so progress would be trivial to print, but at ~17s for a 27k-object repo it finishes before a bar earns its screen space. Documented as a deliberate omission rather than an oversight | n/a |
| `python-dateutil` | `datetime` with explicit Unix-timestamp + timezone parsing of git's `author <ts> <tz>` line format | `parse_commit()` |
| `pydantic` / `attrs` | `dataclasses.dataclass` for the `Rule` and `Finding` structures | `# --- detection ---`, `# --- report ---` |
| `urllib3` / manual percent-decoding | `urllib.parse.unquote`, to decode URL-encoded passwords before checking them against the placeholder list (`pass%23pass` -> `pass#pass`) | `_valid_basic_auth_password()` |
| `cachetools` (`LRUCache`) | `collections.OrderedDict` with `move_to_end` + `popitem(last=False)`, which is all an LRU actually needs | `_BoundedCache` |
| `pyjwt` | `base64.urlsafe_b64decode` + `json.loads` to structurally validate a JWT's header and payload without verifying its signature (we only need to know it is a real JWT, not a valid one) | `_valid_jwt()` |

## Disclosed dev-time use of `git`

`git` itself was used, by a human, exactly twice, and never by the shipped tool or its tests:

1. To build `tests/fixtures/packed_git/`, a pre-built bare repository committed as test data.
   The exact commands are documented in `tests/fixtures/README.md`.
2. During development, to cross-check `histleak`'s object reading against
   `git cat-file --batch-check --batch-all-objects` as a ground-truth oracle on real repositories.

Neither is invoked by `histleak.py`, `test_histleak.py`, or `build_reproducible.py` at runtime.
`git` is not a dependency of the shipped artifact.
