#!/usr/bin/env python3
"""histleak -- find leaked secrets anywhere in a git repository's history,
including files that were later deleted. Standard library only.

No `git` binary is invoked at runtime. This file reads the object database
directly: loose objects, packfiles, and delta chains.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import fnmatch
import json
import math
import mmap
import re
import struct
import sys
import zlib
from collections import Counter, OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import unquote

MAX_BLOB_SIZE = 5 * 1024 * 1024  # skip huge blobs, they're binaries or dumps

# ============================================================
# --- object store ---
# ============================================================
# Reads .git/objects directly. A git object is stored as
#   zlib_compress(b"<type> <size>\0<content>")
# where type is one of commit, tree, blob, tag, and size is the decimal
# byte length of content. The object's id is the SHA-1 of that whole
# decompressed buffer (header included).


def find_git_dir(path: str) -> Path:
    """Walk up from path looking for a .git directory, or accept a bare repo."""
    p = Path(path).resolve()
    if (p / "HEAD").is_file() and (p / "objects").is_dir():
        return p  # bare repo given directly
    cur = p
    while True:
        candidate = cur / ".git"
        if candidate.is_dir():
            return candidate
        if candidate.is_file():
            # gitdir: <path> pointer (worktrees, submodules)
            text = candidate.read_text().strip()
            if text.startswith("gitdir:"):
                target = Path(text.split(":", 1)[1].strip())
                if not target.is_absolute():
                    target = (cur / target).resolve()
                return target
        if cur.parent == cur:
            raise FileNotFoundError(f"no .git directory found above {path}")
        cur = cur.parent


def read_loose(git_dir: Path, sha: str) -> Optional[bytes]:
    """Read and inflate a loose object by its 40-char hex sha. Returns the
    raw decompressed buffer (header + content), or None if not present."""
    obj_path = git_dir / "objects" / sha[:2] / sha[2:]
    if not obj_path.is_file():
        return None
    with open(obj_path, "rb") as f:
        raw = zlib.decompress(f.read())
    return raw


def parse_object_header(raw: bytes) -> tuple[str, int, bytes]:
    """Split a decompressed object buffer into (type, size, content)."""
    nul = raw.index(b"\0")
    header = raw[:nul].decode("ascii")
    otype, size_s = header.split(" ", 1)
    content = raw[nul + 1:]
    return otype, int(size_s), content


class _BoundedCache:
    """LRU cache holding decompressed object contents.

    The cache exists so that a delta base referenced by many deltas is
    inflated once rather than once per dependant. It must be bounded: a
    scan resolves *every* object in the repository, so an unbounded cache
    holds the entire decompressed repo in memory. Measured on requests'
    history (27k objects), unbounded peaked at 172MB, which extrapolates
    to multiple GB on a repo the size of CPython.

    Delta chains have strong locality (a base and its deltas are written
    near each other in the pack), so a small window retains almost all of
    the benefit. Large objects are never cached: they are rarely delta
    bases and dominate memory when they are.
    """

    def __init__(self, max_entries: int = 2048, max_value_bytes: int = 1 << 20):
        self._data: OrderedDict = OrderedDict()
        self._max_entries = max_entries
        self._max_value_bytes = max_value_bytes

    def get(self, key):
        value = self._data.get(key)
        if value is not None:
            self._data.move_to_end(key)
        return value

    def put(self, key, value) -> None:
        if len(value[1]) > self._max_value_bytes:
            return
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self._max_entries:
            self._data.popitem(last=False)


class ObjectStore:
    """Resolves object ids to (type, content) across loose objects and any
    number of packfiles, with delta resolution and bounded memoisation."""

    def __init__(self, git_dir: Path):
        self.git_dir = git_dir
        self.packs: list["PackFile"] = []
        pack_dir = git_dir / "objects" / "pack"
        if pack_dir.is_dir():
            for idx_path in sorted(pack_dir.glob("*.idx")):
                pack_path = idx_path.with_suffix(".pack")
                if pack_path.is_file():
                    self.packs.append(PackFile(idx_path, pack_path))
        self._cache = _BoundedCache()

    def get(self, sha: str) -> Optional[tuple[str, bytes]]:
        cached = self._cache.get(sha)
        if cached is not None:
            return cached
        raw = read_loose(self.git_dir, sha)
        if raw is not None:
            otype, _size, content = parse_object_header(raw)
            result = (otype, content)
            self._cache.put(sha, result)
            return result
        for pack in self.packs:
            result = pack.get(sha, self)
            if result is not None:
                self._cache.put(sha, result)
                return result
        return None

    def iter_loose_shas(self) -> Iterator[str]:
        objects_dir = self.git_dir / "objects"
        if not objects_dir.is_dir():
            return
        for sub in objects_dir.iterdir():
            if not sub.is_dir() or len(sub.name) != 2:
                continue
            if sub.name in ("pack", "info"):
                continue
            for f in sub.iterdir():
                if len(f.name) == 38:
                    yield sub.name + f.name

    def iter_all_shas(self) -> Iterator[str]:
        seen: set[str] = set()
        for sha in self.iter_loose_shas():
            if sha not in seen:
                seen.add(sha)
                yield sha
        for pack in self.packs:
            for sha in pack.index.all_shas():
                if sha not in seen:
                    seen.add(sha)
                    yield sha

    def resolve_ref(self, name: str = "HEAD") -> Optional[str]:
        ref_path = self.git_dir / name
        if ref_path.is_file():
            text = ref_path.read_text().strip()
            if text.startswith("ref:"):
                return self.resolve_ref(text.split(":", 1)[1].strip())
            if re.fullmatch(r"[0-9a-f]{40}", text):
                return text
        packed = self.git_dir / "packed-refs"
        if packed.is_file():
            for line in packed.read_text().splitlines():
                if line.startswith("#") or not line.strip():
                    continue
                parts = line.split()
                if len(parts) == 2 and parts[1] == name:
                    return parts[0]
        return None

    def all_ref_shas(self) -> list[str]:
        shas: set[str] = set()
        heads_dir = self.git_dir / "refs"
        if heads_dir.is_dir():
            for f in heads_dir.rglob("*"):
                if f.is_file():
                    text = f.read_text().strip()
                    if re.fullmatch(r"[0-9a-f]{40}", text):
                        shas.add(text)
        packed = self.git_dir / "packed-refs"
        if packed.is_file():
            for line in packed.read_text().splitlines():
                if line.startswith("#") or not line.strip() or line.startswith("^"):
                    continue
                parts = line.split()
                if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{40}", parts[0]):
                    shas.add(parts[0])
        head = self.resolve_ref("HEAD")
        if head:
            shas.add(head)
        return sorted(shas)


# ============================================================
# --- packfile ---
# ============================================================
# A .idx file (version 2) is a sorted index over the objects packed in the
# matching .pack file: a 256-entry fanout table by first sha byte, a sorted
# sha table, a crc table, a 31-bit offset table, and an overflow 64-bit
# offset table for objects beyond the 2GB mark.
#
# A .pack file is a sequence of objects, each with a variable-length
# type+size header followed by zlib-compressed content. Two of the seven
# object types are deltas (OFS_DELTA, REF_DELTA): their "content" is a
# copy/insert instruction stream applied against a base object, which may
# itself be a delta. Chains are resolved recursively and memoised.

PACK_TYPE_NAMES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
OBJ_OFS_DELTA = 6
OBJ_REF_DELTA = 7


class PackIndex:
    def __init__(self, idx_path: Path):
        with open(idx_path, "rb") as f:
            data = f.read()
        if data[:4] != b"\xfftOc" or struct.unpack(">I", data[4:8])[0] != 2:
            raise ValueError(f"unsupported pack index format: {idx_path}")
        fanout = struct.unpack(">256I", data[8:8 + 256 * 4])
        self.count = fanout[255]
        off = 8 + 256 * 4
        sha_table_off = off
        off += 20 * self.count
        crc_table_off = off  # noqa: unused, present for structural completeness
        off += 4 * self.count
        offset_table_off = off
        off += 4 * self.count
        large_offset_table_off = off

        self._data = data
        self._sha_table_off = sha_table_off
        self._offset_table_off = offset_table_off
        self._large_offset_table_off = large_offset_table_off
        self.fanout = fanout

    def _sha_at(self, i: int) -> str:
        base = self._sha_table_off + i * 20
        return self._data[base:base + 20].hex()

    def _offset_at(self, i: int) -> int:
        base = self._offset_table_off + i * 4
        raw = struct.unpack(">I", self._data[base:base + 4])[0]
        if raw & 0x80000000:
            large_i = raw & 0x7FFFFFFF
            lbase = self._large_offset_table_off + large_i * 8
            return struct.unpack(">Q", self._data[lbase:lbase + 8])[0]
        return raw

    def find_offset(self, sha: str) -> Optional[int]:
        first_byte = int(sha[:2], 16)
        lo = self.fanout[first_byte - 1] if first_byte > 0 else 0
        hi = self.fanout[first_byte]
        while lo < hi:
            mid = (lo + hi) // 2
            mid_sha = self._sha_at(mid)
            if mid_sha == sha:
                return self._offset_at(mid)
            if mid_sha < sha:
                lo = mid + 1
            else:
                hi = mid
        return None

    def all_shas(self) -> Iterator[str]:
        for i in range(self.count):
            yield self._sha_at(i)


def _read_varint_size(buf: bytes, pos: int) -> tuple[int, int]:
    """Object-header style size varint: 7 bits per byte, little-endian order,
    continuation in the MSB. Returns (value, new_pos)."""
    byte = buf[pos]
    value = byte & 0x7F
    shift = 7
    pos += 1
    while byte & 0x80:
        byte = buf[pos]
        value |= (byte & 0x7F) << shift
        shift += 7
        pos += 1
    return value, pos


def _read_ofs_delta_offset(buf: bytes, pos: int) -> tuple[int, int]:
    """OFS_DELTA's negative-offset varint. Different carry rule from the
    size varint: each continued byte adds 1 before shifting in (git's
    "offset encoding")."""
    byte = buf[pos]
    value = byte & 0x7F
    pos += 1
    while byte & 0x80:
        byte = buf[pos]
        pos += 1
        value = ((value + 1) << 7) | (byte & 0x7F)
    return value, pos


def _apply_delta(base: bytes, delta: bytes) -> bytes:
    pos = 0
    src_size, pos = _read_varint_size(delta, pos)
    if src_size != len(base):
        raise ValueError("delta base size mismatch")
    target_size, pos = _read_varint_size(delta, pos)
    out = bytearray()
    n = len(delta)
    while pos < n:
        op = delta[pos]
        pos += 1
        if op & 0x80:
            offset = 0
            size = 0
            for i in range(4):
                if op & (1 << i):
                    offset |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if op & (0x10 << i):
                    size |= delta[pos] << (8 * i)
                    pos += 1
            if size == 0:
                size = 0x10000
            out += base[offset:offset + size]
        elif op != 0:
            length = op & 0x7F
            out += delta[pos:pos + length]
            pos += length
        else:
            raise ValueError("invalid delta opcode 0")
    if len(out) != target_size:
        raise ValueError("delta target size mismatch")
    return bytes(out)


class PackFile:
    def __init__(self, idx_path: Path, pack_path: Path):
        self.index = PackIndex(idx_path)
        self.pack_path = pack_path
        self._fh = open(pack_path, "rb")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        self._offset_cache = _BoundedCache()

    def __del__(self):
        try:
            self._mm.close()
            self._fh.close()
        except Exception:
            pass

    def get(self, sha: str, store: "ObjectStore") -> Optional[tuple[str, bytes]]:
        offset = self.index.find_offset(sha)
        if offset is None:
            return None
        return self._resolve_at(offset, store)

    def _resolve_at(self, offset: int, store: "ObjectStore") -> tuple[str, bytes]:
        cached = self._offset_cache.get(offset)
        if cached is not None:
            return cached

        mm = self._mm
        pos = offset
        byte = mm[pos]
        obj_type = (byte >> 4) & 0x7
        size = byte & 0x0F
        shift = 4
        pos += 1
        while byte & 0x80:
            byte = mm[pos]
            size |= (byte & 0x7F) << shift
            shift += 7
            pos += 1

        if obj_type == OBJ_OFS_DELTA:
            neg_offset, pos = _read_ofs_delta_offset(mm, pos)
            base_offset = offset - neg_offset
            base_type, base_content = self._resolve_at(base_offset, store)
            content = self._inflate_from(pos)
            result_content = _apply_delta(base_content, content)
            result = (base_type, result_content)
        elif obj_type == OBJ_REF_DELTA:
            base_sha = mm[pos:pos + 20].hex()
            pos += 20
            base = store.get(base_sha)
            if base is None:
                raise ValueError(f"missing delta base {base_sha}")
            base_type, base_content = base
            content = self._inflate_from(pos)
            result_content = _apply_delta(base_content, content)
            result = (base_type, result_content)
        else:
            content = self._inflate_from(pos)
            result = (PACK_TYPE_NAMES[obj_type], content)

        self._offset_cache.put(offset, result)
        return result

    def _inflate_from(self, pos: int) -> bytes:
        d = zlib.decompressobj()
        # Decompress in a bounded window; zlib stops consuming once the
        # stream ends, so a generous slice is safe and avoids reading the
        # whole (possibly huge) packfile into the decompressor at once.
        chunk = self._mm[pos:pos + (1 << 20)]
        out = d.decompress(chunk)
        while not d.eof and len(chunk) == (1 << 20):
            pos += len(chunk)
            chunk = self._mm[pos:pos + (1 << 20)]
            if not chunk:
                break
            out += d.decompress(chunk)
        return out


# ============================================================
# --- detection ---
# ============================================================
# Each rule is a regex plus an optional structural validator that runs on
# the match before it is reported, to cut false positives on things that
# merely look like a key (test fixtures, hashes, base64 blobs).


def _luhn_like_github_pat(token: str) -> bool:
    # GitHub PATs (ghp_/gho_/ghu_/ghs_/ghr_) are 36 base62 chars after the
    # prefix. No public checksum; length/charset is the practical check.
    body = token.split("_", 1)[-1]
    return len(body) == 36 and re.fullmatch(r"[A-Za-z0-9]{36}", body) is not None


def _valid_aws_key(token: str) -> bool:
    return re.fullmatch(r"(AKIA|ASIA)[A-Z0-9]{16}", token) is not None


def _valid_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        for part in parts[:2]:
            pad = "=" * (-len(part) % 4)
            json.loads(base64.urlsafe_b64decode(part + pad))
        return True
    except Exception:
        return False


# Words that appear as the password in documentation and test URLs. Testing
# against `requests`' own history, every single basic-auth match in 27k
# objects was one of these -- "pass", "password", "{ENCODED_PASSWORD}" --
# and none was a real credential. Without this filter the rule produced
# 1,960 findings on a clean repository, which is worse than useless: it
# trains people to ignore the tool.
_PLACEHOLDER_PASSWORDS = frozenset({
    "pass", "password", "passwd", "pwd", "secret", "mypassword", "yourpassword",
    "changeme", "change_me", "user", "username", "token", "apikey", "api_key",
    "test", "testing", "example", "sample", "demo", "placeholder", "redacted",
    "hidden", "xxx", "xxxx", "yyy", "zzz", "foo", "bar", "baz", "hunter2",
    "abc123", "123456", "letmein", "admin", "root", "none", "null", "value",
})


_TEMPLATE_SYNTAX = re.compile(
    r"\$\{.*?\}"          # ${VAR}
    r"|\{[^}]*\}"          # {PLACEHOLDER}
    r"|<[^>]*>"            # <your-password>
    r"|%\([^)]*\)[sd]"     # %(name)s
    r"|%[sd]\b"            # %s / %d
)
# "$VAR" only counts as a template when it is the whole value. Kept out of
# the alternation above because "$" there would read as an end anchor and
# reject any password merely ending in "$something".
_BARE_SHELL_VAR = re.compile(r"\A\$[A-Za-z_][A-Za-z0-9_]*\Z")


def _valid_basic_auth_password(password: str) -> bool:
    """Reject documentation placeholders in scheme://user:pass@host URLs."""
    decoded = unquote(password).strip()
    if len(decoded) < 6:
        return False
    # Template syntax, not the individual characters: "$" and "*" are
    # perfectly ordinary password characters, so only reject them when they
    # form an actual substitution -- ${VAR}, {PLACEHOLDER}, <your-password>,
    # %s, %(name)s.
    if _TEMPLATE_SYNTAX.search(decoded) or _BARE_SHELL_VAR.match(decoded):
        return False
    lowered = decoded.lower()
    if lowered in _PLACEHOLDER_PASSWORDS:
        return False
    # "pass pass", "password-password", "pass#pass": a placeholder repeated
    # or joined by any separator. Split on every non-alphanumeric character
    # so URL-encoded separators (%23 -> "#") are handled after unquoting.
    words = re.split(r"[^a-z0-9]+", lowered)
    if words and all(w in _PLACEHOLDER_PASSWORDS or not w for w in words):
        return False
    if len(set(decoded)) <= 2:
        return False  # "aaaaaa", "abababab"
    return True


@dataclass
class Rule:
    id: str
    severity: str
    pattern: re.Pattern
    validator: Optional[callable] = None
    group: int = 0

    def scan(self, text: str) -> Iterator[str]:
        for m in self.pattern.finditer(text):
            token = m.group(self.group)
            if self.validator is None or self.validator(token):
                yield token


RULES: list[Rule] = [
    Rule("aws-access-key-id", "high",
         re.compile(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b"), _valid_aws_key),
    Rule("aws-secret-access-key", "high",
         re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?")),
    Rule("github-pat", "high",
         re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36})\b"), _luhn_like_github_pat),
    Rule("stripe-live-key", "high",
         re.compile(r"\b(sk_live_[A-Za-z0-9]{24,})\b")),
    Rule("stripe-restricted-key", "high",
         re.compile(r"\b(rk_live_[A-Za-z0-9]{24,})\b")),
    Rule("slack-token", "high",
         re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    Rule("google-api-key", "medium",
         re.compile(r"\b(AIza[A-Za-z0-9_\-]{35})\b")),
    Rule("openai-api-key", "high",
         re.compile(r"\b(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_\-]{20,})\b")),
    Rule("anthropic-api-key", "high",
         re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b")),
    Rule("private-key-block", "high",
         re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    Rule("jwt", "medium",
         re.compile(r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b"), _valid_jwt),
    Rule("generic-api-key-assignment", "low",
         re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-/+]{16,})['\"]")),
    Rule("basic-auth-url", "medium",
         re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:([^/\s:@]{4,})@"),
         _valid_basic_auth_password, group=1),
    Rule("slack-webhook", "medium",
         re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})")),
    Rule("npm-token", "medium",
         re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
]

# Deliberately excludes "-" and "_": English slugs and doc anchors
# ("some-long-hyphenated-heading") are long, mixed-case-ish, and genuinely
# high entropy by Shannon's formula, so charset is doing the filtering
# that entropy alone can't. A real secret rarely needs a hyphen to stay
# under 80 characters.
_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/=]{20,}")
_ENTROPY_MIN_BITS = 4.5
_HAS_DIGIT = re.compile(r"\d")
_HAS_ALPHA = re.compile(r"[A-Za-z]")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_like_secret(token: str) -> bool:
    # Real secrets mix letters and digits; camelCase identifiers and URL
    # path segments overwhelmingly don't carry digits at this length.
    if not (_HAS_DIGIT.search(token) and _HAS_ALPHA.search(token)):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", token):
        return False  # hex hashes/shas are high-entropy but not secrets
    if "/" in token and token.count("/") >= 2:
        return False  # multi-segment URL/file paths
    return shannon_entropy(token) >= _ENTROPY_MIN_BITS


@dataclass
class Finding:
    rule_id: str
    severity: str
    match: str
    path: str
    line: int
    blob_sha: str
    commit_sha: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    occurrences: int = 1  # how many distinct blobs carried this same secret

    def redacted(self) -> str:
        """Show enough to identify the secret, never enough to use it.

        PEM armor is exempt: "-----BEGIN RSA PRIVATE KEY-----" is a label,
        not key material, and redacting it to "----…----" tells the reader
        nothing about what was found.
        """
        m = self.match
        if m.startswith("-----BEGIN"):
            return m
        if len(m) <= 8:
            return "*" * len(m)
        return m[:4] + "…" + m[-4:]


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

_MAX_ENTROPY_HITS_PER_BLOB = 25

# PEM armor: the base64 body of a certificate is high-entropy by design and
# is public data, not a secret. Private keys are caught by the dedicated
# private-key-block rule, which fires on the BEGIN line itself, so excluding
# armored bodies from the entropy pass loses no real detection.
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----(.*?)-----END [A-Z0-9 ]+-----", re.DOTALL)


def _pem_body_ranges(text: str) -> list[tuple[int, int]]:
    return [(m.start(1), m.end(1)) for m in _PEM_BLOCK.finditer(text)]


def scan_blob_text(text: str, path: str, blob_sha: str,
                   min_severity: str = "low") -> list[Finding]:
    """Scan one blob's text. Rules below min_severity are skipped rather
    than run and filtered afterwards, which matters because the entropy
    pass is the most expensive scan and is only ever low severity."""
    min_rank = SEVERITY_RANK.get(min_severity, 0)

    # Collect (rule_id, severity, token, offset) first. Line numbers need a
    # table of line-start offsets, and building that means walking the whole
    # blob -- wasteful for the overwhelming majority of blobs, which match
    # nothing at all. Defer it until we know there is something to report.
    raw_hits: list[tuple[str, str, str, int]] = []

    for rule in RULES:
        if SEVERITY_RANK[rule.severity] < min_rank:
            continue
        for m in rule.pattern.finditer(text):
            token = m.group(rule.group)
            if rule.validator and not rule.validator(token):
                continue
            raw_hits.append((rule.id, rule.severity, token, m.start()))

    if min_rank == 0:
        seen = {(token, off) for _, _, token, off in raw_hits}
        armored = _pem_body_ranges(text)
        entropy_hits: list[tuple[str, str, str, int]] = []
        for m in _ENTROPY_CANDIDATE.finditer(text):
            token = m.group(0)
            start = m.start()
            if (token, start) in seen:
                continue
            if any(lo <= start < hi for lo, hi in armored):
                continue
            if _looks_like_secret(token):
                entropy_hits.append(("high-entropy-string", "low", token, start))
        # A file where high-entropy strings dominate is an encoded data file
        # (a cert bundle, a minified bundle, an embedded image), not source
        # code with a key in it. Reporting hundreds of lines from one such
        # file drowns every real finding, so treat density as the signal it
        # is and drop the whole blob's entropy hits.
        if len(entropy_hits) <= _MAX_ENTROPY_HITS_PER_BLOB:
            raw_hits.extend(entropy_hits)

    if not raw_hits:
        return []

    line_starts = [0]
    for m in re.finditer(r"\n", text):
        line_starts.append(m.end())

    def line_of(offset: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    return [Finding(rule_id, severity, token, path, line_of(off), blob_sha)
            for rule_id, severity, token, off in raw_hits]


# ============================================================
# --- attribution ---
# ============================================================
# Pass 1 (see scan_repository) finds secrets by scanning every blob in the
# object database directly, which is what catches secrets in files that
# were later deleted -- a deleted file's blob is still in the database,
# just unreachable from the current tree. This section only runs for the
# small set of blobs that actually produced a finding, to answer "which
# commit introduced this, and under what path."



def parse_commit(content: bytes) -> dict:
    text = content.decode("utf-8", errors="replace")
    tree = None
    parents: list[str] = []
    author = None
    ts = 0
    for line in text.split("\n"):
        if not line:
            break
        if line.startswith("tree "):
            tree = line[5:].strip()
        elif line.startswith("parent "):
            parents.append(line[7:].strip())
        elif line.startswith("author "):
            m = re.match(r"author (.+) <(.+)> (\d+) ([+-]\d{4})", line)
            if m:
                author = f"{m.group(1)} <{m.group(2)}>"
                ts = int(m.group(3))
    date = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat() if ts else None
    return {"tree": tree, "parents": parents, "author": author, "date": date, "ts": ts}


def parse_tree(content: bytes) -> list[tuple[str, str, str]]:
    entries = []
    i, n = 0, len(content)
    while i < n:
        sp = content.index(b" ", i)
        mode = content[i:sp].decode("ascii")
        nul = content.index(b"\0", sp + 1)
        name = content[sp + 1:nul].decode("utf-8", errors="replace")
        sha = content[nul + 1:nul + 21].hex()
        entries.append((mode, name, sha))
        i = nul + 21
    return entries


def _commit_generations(commits: list[tuple[str, dict]]) -> dict[str, int]:
    """Longest-path-from-a-root depth for each commit, computed iteratively.

    Iterative rather than recursive: commit graphs are deep (tens of
    thousands of commits in a linear history) and recursion would exhaust
    the stack on exactly the repositories this tool is meant for.
    """
    info_by_sha = {sha: info for sha, info in commits}
    generation: dict[str, int] = {}
    for start, _ in commits:
        if start in generation:
            continue
        stack = [start]
        while stack:
            sha = stack[-1]
            info = info_by_sha.get(sha)
            if info is None:          # parent outside this repo (shallow clone)
                generation[sha] = 0
                stack.pop()
                continue
            pending = [p for p in info["parents"]
                       if p not in generation and p in info_by_sha]
            if pending:
                stack.extend(pending)
                continue
            known = [generation[p] for p in info["parents"] if p in generation]
            generation[sha] = 1 + max(known) if known else 0
            stack.pop()
    return generation


def attribute_blobs(store: ObjectStore, flagged: set[str]) -> dict[str, dict]:
    """For each flagged blob sha, find the earliest commit whose tree
    contains it, and the path it was found under."""
    result: dict[str, dict] = {}
    if not flagged:
        return result

    commits: list[tuple[str, dict]] = []
    seen: set[str] = set()
    queue = list(store.all_ref_shas())
    while queue:
        csha = queue.pop()
        if csha in seen:
            continue
        seen.add(csha)
        got = store.get(csha)
        if got is None:
            continue
        otype, content = got
        if otype != "commit":
            continue
        info = parse_commit(content)
        commits.append((csha, info))
        queue.extend(info["parents"])
    # Sorting by timestamp alone is not enough to find which commit
    # *introduced* a blob: git timestamps have one-second resolution, and
    # scripted commits, rebases, and imports routinely produce several
    # commits sharing a second. When that happens the tie breaks
    # arbitrarily and a child can sort before its own parent, attributing
    # the leak to the commit after the one that actually added it.
    #
    # Generation number (longest path back to a root) is a topological
    # tiebreak: a parent's generation is always strictly less than its
    # child's, so (timestamp, generation) never inverts a real edge.
    generation = _commit_generations(commits)
    commits.sort(key=lambda c: (c[1]["ts"], generation[c[0]]))

    def walk(tree_sha: str, prefix: str, csha: str, info: dict):
        got = store.get(tree_sha)
        if got is None:
            return
        otype, content = got
        if otype != "tree":
            return
        for mode, name, sha in parse_tree(content):
            path = f"{prefix}{name}"
            if mode.startswith("4"):
                walk(sha, path + "/", csha, info)
            elif sha in flagged and sha not in result:
                result[sha] = {"path": path, "commit": csha,
                                "author": info["author"], "date": info["date"]}

    for csha, info in commits:
        if len(result) >= len(flagged):
            break
        if info["tree"]:
            walk(info["tree"], "", csha, info)

    return result


# ============================================================
# --- scan orchestration ---
# ============================================================

def load_ignore_patterns(repo_root: Path) -> list[str]:
    ignore_file = repo_root / ".histleakignore"
    if not ignore_file.is_file():
        return []
    patterns = []
    for line in ignore_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def is_binary_blob(content: bytes) -> bool:
    return b"\0" in content[:8000]


def scan_repository(repo_path: str, min_severity: str = "low") -> list[Finding]:
    git_dir = find_git_dir(repo_path)
    repo_root = git_dir.parent if git_dir.name == ".git" else git_dir
    store = ObjectStore(git_dir)
    ignore_patterns = load_ignore_patterns(repo_root)


    findings_by_blob: dict[str, list[Finding]] = {}
    for sha in store.iter_all_shas():
        got = store.get(sha)
        if got is None:
            continue
        otype, content = got
        if otype != "blob":
            continue
        if len(content) > MAX_BLOB_SIZE or len(content) == 0:
            continue
        if is_binary_blob(content):
            continue
        text = content.decode("utf-8", errors="replace")
        blob_findings = scan_blob_text(text, path="", blob_sha=sha,
                                        min_severity=min_severity)
        if blob_findings:
            findings_by_blob[sha] = blob_findings

    attribution = attribute_blobs(store, set(findings_by_blob.keys()))

    all_findings: list[Finding] = []
    for sha, flist in findings_by_blob.items():
        info = attribution.get(sha)
        path = info["path"] if info else "(unreachable from any ref)"
        if ignore_patterns and any(fnmatch.fnmatch(path, pat) for pat in ignore_patterns):
            continue
        for f in flist:
            f.path = path
            if info:
                f.commit_sha = info["commit"]
                f.author = info["author"]
                f.date = info["date"]
            all_findings.append(f)

    all_findings = _deduplicate(all_findings)
    all_findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line))
    return all_findings


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse the same secret found in many historical versions of a file.

    Every commit that touched a file creates a new blob, so a secret that
    survived twenty commits is twenty distinct blobs carrying identical
    content. Reporting each one separately buries the signal: what the user
    needs is "this secret is in this file, first introduced here, and it
    persisted across N versions."
    """
    grouped: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.rule_id, f.match, f.path, f.line)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = f
            continue
        existing.occurrences += 1
        # Keep the earliest attribution: that is when the leak was introduced.
        if f.date and (existing.date is None or f.date < existing.date):
            existing.commit_sha = f.commit_sha
            existing.author = f.author
            existing.date = f.date
            existing.blob_sha = f.blob_sha
    return list(grouped.values())


# ============================================================
# --- report ---
# ============================================================

SEVERITY_LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW "}


def print_text_report(findings: list[Finding], repo_path: str) -> None:
    if not findings:
        print(f"histleak: no secrets found in {repo_path}")
        return
    print(f"histleak: {len(findings)} finding(s) in {repo_path}\n")
    for f in findings:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        commit = f.commit_sha[:8] if f.commit_sha else "unknown"
        when = f" ({f.date})" if f.date else ""
        print(f"  {SEVERITY_LABEL[f.severity]}  {f.rule_id:<28} {loc}")
        versions = f" across {f.occurrences} versions" if f.occurrences > 1 else ""
        print(f"        first seen in commit {commit}{when}{versions}")
        print(f"        {f.redacted()}")
    print(f"\n{len(findings)} finding(s). "
          f"Use `git log --all --oneline | grep <commit>` to inspect, "
          f"or add a glob to .histleakignore to suppress.")


def findings_to_json(findings: list[Finding]) -> list[dict]:
    return [{
        "rule_id": f.rule_id,
        "severity": f.severity,
        "match": f.redacted(),
        "path": f.path,
        "line": f.line,
        "blob_sha": f.blob_sha,
        "occurrences": f.occurrences,
        "commit_sha": f.commit_sha,
        "author": f.author,
        "date": f.date,
    } for f in findings]


# ============================================================
# --- cli ---
# ============================================================

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="histleak",
        description="Find leaked secrets anywhere in a git repository's history, "
                    "including deleted files. Standard library only.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a repository's full object history")
    scan_p.add_argument("path", nargs="?", default=".", help="path to a git repo (default: .)")
    scan_p.add_argument("--format", choices=["text", "json"], default="text")
    scan_p.add_argument("--severity", choices=["low", "medium", "high"], default="medium",
                         help="minimum severity to report (default: medium; "
                              "'low' also enables the noisier entropy detector)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            findings = scan_repository(args.path, min_severity=args.severity)
        except FileNotFoundError as e:
            print(f"histleak: {e}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"histleak: error: {e}", file=sys.stderr)
            return 2

        if args.format == "json":
            print(json.dumps(findings_to_json(findings), indent=2))
        else:
            print_text_report(findings, args.path)

        return 1 if findings else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
