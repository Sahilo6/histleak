#!/usr/bin/env python3
"""histleak -- find leaked secrets anywhere in a git repository's history,
including files that were later deleted. Standard library only.

No `git` binary is invoked at runtime. This file reads the object database
directly: loose objects, packfiles, and delta chains.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import mmap
import re
import struct
import sys
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

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


class ObjectStore:
    """Resolves object ids to (type, content) across loose objects and any
    number of packfiles, with delta resolution and memoisation."""

    def __init__(self, git_dir: Path):
        self.git_dir = git_dir
        self.packs: list["PackFile"] = []
        pack_dir = git_dir / "objects" / "pack"
        if pack_dir.is_dir():
            for idx_path in sorted(pack_dir.glob("*.idx")):
                pack_path = idx_path.with_suffix(".pack")
                if pack_path.is_file():
                    self.packs.append(PackFile(idx_path, pack_path))
        self._cache: dict[str, tuple[str, bytes]] = {}

    def get(self, sha: str) -> Optional[tuple[str, bytes]]:
        cached = self._cache.get(sha)
        if cached is not None:
            return cached
        raw = read_loose(self.git_dir, sha)
        if raw is not None:
            otype, _size, content = parse_object_header(raw)
            result = (otype, content)
            self._cache[sha] = result
            return result
        for pack in self.packs:
            result = pack.get(sha, self)
            if result is not None:
                self._cache[sha] = result
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
        self._offset_cache: dict[int, tuple[str, bytes]] = {}

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

        self._offset_cache[offset] = result
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
            json.loads(__import__("base64").urlsafe_b64decode(part + pad))
        return True
    except Exception:
        return False


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
         re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:([^/\s:@]{4,})@")),
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

    def redacted(self) -> str:
        m = self.match
        if len(m) <= 8:
            return "*" * len(m)
        return m[:4] + "…" + m[-4:]


def scan_blob_text(text: str, path: str, blob_sha: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.split("\n")
    line_starts = []
    pos = 0
    for line in lines:
        line_starts.append(pos)
        pos += len(line) + 1

    def line_of(offset: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    for rule in RULES:
        for m in rule.pattern.finditer(text):
            token = m.group(rule.group)
            if rule.validator and not rule.validator(token):
                continue
            findings.append(Finding(rule.id, rule.severity, token, path,
                                     line_of(m.start()), blob_sha))

    seen_spans = {(f.match, f.line) for f in findings}
    for m in _ENTROPY_CANDIDATE.finditer(text):
        token = m.group(0)
        key = (token, line_of(m.start()))
        if key in seen_spans:
            continue
        if _looks_like_secret(token):
            findings.append(Finding("high-entropy-string", "low", token, path,
                                     line_of(m.start()), blob_sha))
    return findings


# ============================================================
# --- attribution ---
# ============================================================
# Pass 1 (see scan_repository) finds secrets by scanning every blob in the
# object database directly, which is what catches secrets in files that
# were later deleted -- a deleted file's blob is still in the database,
# just unreachable from the current tree. This section only runs for the
# small set of blobs that actually produced a finding, to answer "which
# commit introduced this, and under what path."

import datetime as _datetime


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
    date = _datetime.datetime.fromtimestamp(ts, tz=_datetime.timezone.utc).isoformat() if ts else None
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
    commits.sort(key=lambda c: c[1]["ts"])

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

    severity_rank = {"low": 0, "medium": 1, "high": 2}
    min_rank = severity_rank.get(min_severity, 0)

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
        blob_findings = scan_blob_text(text, path="", blob_sha=sha)
        blob_findings = [f for f in blob_findings if severity_rank[f.severity] >= min_rank]
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

    all_findings.sort(key=lambda f: (-severity_rank[f.severity], f.path, f.line))
    return all_findings


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
        print(f"        commit {commit}{when}  blob {f.blob_sha[:10]}")
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
