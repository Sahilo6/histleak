# Decoding a git packfile with nothing but zlib and struct

I built `histleak`, a secret scanner that reads a git repository's object database directly,
for the Zero Dependency 2026 hackathon. The rule is standard library only. No GitPython, no
`git` subprocess. This is the story of the one piece that actually fought back: the packfile
delta resolver.

## The part that looked easy and wasn't

Reading a loose object is genuinely three lines:

```python
raw = zlib.decompress(open(obj_path, "rb").read())
otype, size = raw[:raw.index(b"\0")].decode().split(" ")
content = raw[raw.index(b"\0") + 1:]
```

Inflate, split the header, done. I validated this against a real repo on my machine before
writing anything else, and it matched `git cat-file` exactly on the first try.

Then I ran `git gc` and every loose object disappeared into a single `.pack` file, and the easy
part was over. Every repository cloned from GitHub ships this way. If `histleak` couldn't read
packfiles, it couldn't read anything a stranger would actually hand it.

## What a packfile actually is

A `.pack` file is a sequence of objects. Each one starts with a variable-length header encoding
type and size, then zlib-compressed content. Straightforward, except two of the seven object
types aren't content at all -- they're instructions. `OFS_DELTA` and `REF_DELTA` objects store
"copy these bytes from another object, then insert these literal bytes," which is how git
compresses a file that changed by ten lines into a few dozen bytes instead of storing the whole
file again.

The header's size field uses a variable-length integer: 7 bits of value per byte, continuation
flag in the high bit, **little-endian** bit order (least significant chunk first):

```python
def _read_varint_size(buf, pos):
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
```

`OFS_DELTA`'s offset field looks almost identical but is **not** the same encoding. It carries
an implicit `+1` on every continuation byte, because git wanted to avoid two different bit
patterns encoding the same offset:

```python
def _read_ofs_delta_offset(buf, pos):
    byte = buf[pos]
    value = byte & 0x7F
    pos += 1
    while byte & 0x80:
        byte = buf[pos]
        pos += 1
        value = ((value + 1) << 7) | (byte & 0x7F)
    return value, pos
```

I wrote the first version without the `+1` because it's not obvious from the git source that
the two varints differ at all -- they look the same at a glance, one encodes a size and the
other encodes an offset, why would the carry rule change? It does, and the failure mode is
brutal: wrong offsets don't crash, they resolve to a *different real object* that happens to
exist at that byte position, and your delta base is silently wrong. I only caught it because I
was checksum-verifying every resolved object's SHA-1 against its expected id from the start, not
just eyeballing whether the output looked plausible.

## Applying the delta

Once you have the base object and the delta instructions, applying them is an interpreter for a
tiny two-opcode language. The high bit of each opcode byte decides which one:

- **Copy** (high bit set): the low 7 bits are a bitmask over up to 7 following bytes -- 4 for a
  24-bit offset into the base, 3 for a 24-bit length. Any byte the mask omits is implicitly
  zero, and length `0` means `0x10000`, not zero, because nobody encodes a zero-length copy.
- **Insert** (high bit clear): the byte itself is a length, 1-127, and that many literal bytes
  follow.

```python
if op & 0x80:
    offset = size = 0
    for i in range(4):
        if op & (1 << i):
            offset |= delta[pos] << (8 * i); pos += 1
    for i in range(3):
        if op & (0x10 << i):
            size |= delta[pos] << (8 * i); pos += 1
    if size == 0:
        size = 0x10000
    out += base[offset:offset + size]
```

## The bug that only shows up on a real repository

My first working version passed every test against a small hand-built fixture. It hung on a
real cloned repo of about 1,200 objects.

The cause: `OFS_DELTA` bases can themselves be deltas, and delta chains in a real repo run
deep -- one object can be "apply these instructions to the result of applying those instructions
to the result of..." many times over. My resolver was recursive and correct, but it re-resolved
the same base from scratch every time a different delta pointed at it, and with enough deltas
sharing bases the work grows combinatorially. The fix is a one-line memoisation cache keyed by
byte offset in the packfile:

```python
def _resolve_at(self, offset, store):
    cached = self._offset_cache.get(offset)
    if cached is not None:
        return cached
    # ... resolve ...
    self._offset_cache[offset] = result
    return result
```

After adding it, the same 1,200-object repository resolved and SHA-verified every single object
in 90 milliseconds. The lesson generalizes past this project: a delta-chain resolver that's
correct on a 4-object test fixture and untested on anything larger will look completely fine
right up until it meets real data, because small fixtures don't have the shared-base structure
that makes the unmemoised version quadratic (or worse).

## Why this was worth the format-spec archaeology

`histleak`'s entire headline feature -- finding a secret in a file that was deleted three
commits ago -- falls out for free once object reading works, because a deleted file's blob
never actually leaves the object database. It just stops being reachable from the current tree.
None of that required understanding git's *history model* at all. It only required correctly
reading the *object store*, which turned out to be the harder and more interesting problem, and
the one no `pip install` was going to solve for me this weekend.
