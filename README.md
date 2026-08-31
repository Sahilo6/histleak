# histleak

Finds leaked secrets anywhere in a git repository's history, including files that were later
deleted. Standard library only. No `git` binary at runtime, no GitPython, no gitleaks.

Built for [Zero Dependency 2026](https://zerodepshack.com), Track E: Security & Crypto
Utilities.

## Why this exists

`git rm secret.env && git commit` does not remove the secret. It is still sitting in the object
database, reachable by anyone who clones the repo and knows to look. Most scanners either check
the working tree only, or shell out to `git log -p` and grep the diff, which means they still
depend on `git` being installed and on its output format not changing under them.

`histleak` reads the object database directly: it inflates loose objects, parses packfiles,
resolves delta chains, and scans every blob that has ever existed in the repo, whether or not
it is reachable from the current tree.

## Install and run

One file, no install step.

```bash
curl -O https://raw.githubusercontent.com/Sahilo6/histleak/main/histleak.py
python3 histleak.py scan /path/to/some/repo
```

Or build the reproducible zipapp (see [Build](#build) below) and run `./dist/histleak.pyz scan .`

## What it looks like

```
$ python3 histleak.py scan tests/fixtures/packed_git

histleak: 1 finding(s) in tests/fixtures/packed_git

  HIGH  aws-access-key-id            config/prod.env:1
        first seen in commit 892dd7d9 (2024-01-01T18:30:00+00:00)
        AKIA…0001

1 finding(s). Use `git log --all --oneline | grep <commit>` to inspect, or add a glob to .histleakignore to suppress.
$ echo $?
1
```

`config/prod.env` was deleted three commits ago in that fixture repo. It is still found,
correctly attributed to the commit that introduced it, because the blob is still in the pack.

## Usage

```
histleak scan [path]                  # default: current directory, medium severity and up
histleak scan [path] --severity low   # also runs the entropy detector (noisier, catches more)
histleak scan [path] --format json    # machine-readable output for CI
```

Exit codes: `0` clean, `1` findings, `2` error (e.g. not a git repository).

Add a `.histleakignore` file to the repo root with one glob per line to suppress paths you've
reviewed and accepted (test fixtures, intentionally-fake keys in docs, etc):

```
tests/fixtures/*
docs/examples/*
```

## How it works

Two passes, not one. The straightforward approach -- diff every commit's tree against its
parent and scan changed blobs -- works, but it means walking the full commit graph before you
can report anything.

**Pass 1** enumerates every object in the database directly (every loose object, plus every
object indexed by every `.idx`/`.pack` pair), dedupes by sha, and scans every blob. This alone
is the entire "found in deleted history" feature, because a deleted file's blob never leaves the
object database -- it just stops being reachable from `HEAD`'s tree. No tree walking required.

**Pass 2** runs only for the blobs that pass 1 actually flagged: it walks commits from every ref,
parses each tree, and records the earliest commit + path each flagged blob appeared under. Since
real repos have very few findings, an expensive walk over a small set is cheap in practice.

Detection is a table of ~20 structural rules (AWS, Stripe, GitHub, Slack, Google, OpenAI,
Anthropic, JWTs, PEM key blocks, generic key-value assignments, each with a shape validator to
cut false positives) plus a tuned Shannon-entropy detector for `--severity low`. The entropy
detector deliberately excludes `-`/`_` from its candidate charset: natural-language slugs and
doc anchors are long and mixed-case enough to score as "high entropy" by the raw formula, and
excluding hyphens is what actually filters them out, not the entropy threshold. See
`histleak.py`'s `# --- detection ---` section for the reasoning.

## Build

```bash
./build.sh
```

Produces `dist/histleak.pyz`, a standalone zipapp. Byte-identical across runs, because it's
built by hand through `zipfile` with a fixed timestamp on every entry instead of
`python3 -m zipapp` (which stamps the current time and would make every build differ):

```
$ ./build.sh && ./build.sh
wrote dist/histleak.pyz (11990 bytes)
wrote dist/histleak.pyz (11990 bytes)
53d41db4b87abbc7d343ba495130d97a3e3b704d4fdfa207fee24b463f1ef576  dist/histleak.pyz
53d41db4b87abbc7d343ba495130d97a3e3b704d4fdfa207fee24b463f1ef576  dist/histleak.pyz
```

## Tests

```bash
python3 -m unittest -v
```

32 tests, no network, no `git` invoked at test time. `tests/fixtures/packed_git/` is a
pre-built, `git gc`'d bare repo committed as test data -- see `tests/fixtures/README.md` for
exactly how it was built and what it plants. `git` was used once, by a human, to build that
fixture. It is never called by `histleak.py` or by the tests.

## Scale and accuracy

Measured on [psf/requests](https://github.com/psf/requests) full history, 26,859 objects:

| | Default (`--severity medium`) | `--severity low` |
|---|---|---|
| Findings | 4 | 13 |
| False positives | 0 | 0 |
| Time | ~17s | ~21s |
| Peak memory | 87MB | 87MB |

All 4 default findings are real private keys in `tests/certs/`, committed intentionally as test
fixtures. `histleak` is correct to flag them; a user would add them to `.histleakignore`.

Getting there took four fixes that only a repo this size revealed, each now covered by a
regression test:

- **Placeholder credentials.** `http://user:pass@host` in documentation produced **1,960**
  findings. Every basic-auth match in requests' entire history was a placeholder, not a
  credential, so the rule now validates the password against a placeholder list and template
  syntax (`${VAR}`, `{PLACEHOLDER}`, `<your-password>`).
- **Certificate bundles.** `requests/cacert.pem` produced **19,328** entropy findings on its own.
  A certificate's base64 body is high-entropy by design and is public data, so PEM-armored
  bodies are excluded from the entropy pass. Private keys still fire, because that rule matches
  the `BEGIN` line itself.
- **Encoded data files.** Any blob where entropy hits dominate is an encoded artifact, not source
  with a key in it, so its entropy hits are dropped wholesale.
- **Unbounded caching.** The object cache held every decompressed object in the repo, peaking at
  172MB on 27k objects and extrapolating to multiple GB on something CPython-sized. It is now a
  bounded LRU, which cut peak memory roughly in half with no loss of delta-resolution speed.

Findings are also deduplicated: a secret that survived twenty commits is twenty distinct blobs
with identical content, reported once as "first seen in commit X across N versions."

## Limitations

- Scans blobs up to 5MB; larger ones are skipped (binaries, data dumps).
- Binary blobs (NUL byte in the first 8KB) are skipped.
- No live credential verification against provider APIs -- a match means "looks like a key,"
  not "this key is still active."
- Commit attribution finds the earliest commit that introduced a flagged blob at some path. If
  the same secret content was independently added under multiple paths, only the first is
  reported per blob.
- Detection runs on blob content before paths are known, so rules cannot currently be scoped by
  file extension. The density guard covers the cases where that would have helped.

## Zero-dependency proof

```bash
python3 -m venv /tmp/histleak-check && source /tmp/histleak-check/bin/activate
pip freeze   # empty
```

`requirements.txt` is empty. `.github/workflows/ci.yml` has no install step and additionally
walks `histleak.py`'s AST to confirm every import resolves to the Python 3 standard library, on
every push.

See [STDLIB.md](STDLIB.md) for the package-by-package substitution log.

## License

MIT, see [LICENSE](LICENSE).
