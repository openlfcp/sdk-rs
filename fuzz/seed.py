#!/usr/bin/env python3
"""Write the seed corpora of the fuzz targets from the spec corpora.

Reads SHARED-OBJECTS-AUTOMERGE-REFERENCE-01 and
SHARED-SECTIONS-TEST-VECTORS-01 at the commit spec.lock pins, with
`git show`, from $LFCP_SPEC_DIR or ../spec next to this repository, and
writes fuzz/corpus/<target>/<name>. Run from anywhere:

    python3 fuzz/seed.py
"""

import base64
import hashlib
import json
import os
import subprocess
import sys

FUZZ = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(FUZZ)
OBJECTS = "test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json"
SECTIONS = "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json"
MAGIC = bytes([0x85, 0x6F, 0x4A, 0x83])

# The record format of fuzz/src/lib.rs.
CTL_REFRAME = 1 << 2
CTL_FRAME = 1 << 3
CTL_ORIGIN_ESTABLISHED = 1 << 4


def spec_json(path):
    lock = json.load(open(os.path.join(ROOT, "spec.lock")))
    spec = os.environ.get("LFCP_SPEC_DIR", "../spec")
    spec = os.path.join(ROOT, spec)
    out = subprocess.run(
        ["git", "-C", spec, "show", f"{lock['commit']}:{path}"],
        check=True,
        capture_output=True,
    ).stdout
    return json.loads(out)


def uleb(data, at):
    n, shift = 0, 0
    while True:
        b = data[at]
        at += 1
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n, at
        shift += 7


def body_of(chunk):
    """(chunk type, body) of a chunk, or None."""
    if len(chunk) < 10 or chunk[:4] != MAGIC:
        return None
    length, at = uleb(chunk, 9)
    return chunk[8], chunk[at : at + length]


def change_actor(chunk):
    """The hex actor of an uncompressed change chunk."""
    _, body = body_of(chunk)
    deps, at = uleb(body, 0)
    at += 32 * deps
    n, at = uleb(body, at)
    return body[at : at + n].hex()


def frame(payload):
    """[1, bstr] in deterministic CBOR."""
    n = len(payload)
    if n < 24:
        head = bytes([0x40 | n])
    elif n < 0x100:
        head = bytes([0x58, n])
    elif n < 0x10000:
        head = bytes([0x59]) + n.to_bytes(2, "big")
    else:
        head = bytes([0x5A]) + n.to_bytes(4, "big")
    return bytes([0x82, 0x01]) + head + payload


def record(ctl, data):
    return bytes([ctl]) + len(data).to_bytes(2, "little") + data


def records(chunks, signer_of, reframe=False):
    out = b""
    for c in chunks:
        if len(c) > 0xFFFF - 1:
            return None
        ctl = signer_of(c)
        if reframe and body_of(c):
            t, body = body_of(c)
            out += record(ctl | CTL_REFRAME, bytes([t]) + body)
        else:
            out += record(ctl | CTL_FRAME, c)
    return out


class Corpus:
    def __init__(self, target):
        self.dir = os.path.join(FUZZ, "corpus", target)
        os.makedirs(self.dir, exist_ok=True)
        self.count = 0

    def add(self, name, data, limit=None):
        if data is None or (limit and len(data) > limit):
            return
        digest = hashlib.sha256(data).hexdigest()[:12]
        with open(os.path.join(self.dir, f"{name}-{digest}"), "wb") as f:
            f.write(data)
        self.count += 1


def hex_values(node, out):
    """Every *_hex value of a JSON tree that is a chunk."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k.endswith("hex") and isinstance(v, str) and v.startswith("856f4a83"):
                out.append(bytes.fromhex(v))
            else:
                hex_values(v, out)
    elif isinstance(node, list):
        for v in node:
            hex_values(v, out)


def main():
    objects = spec_json(OBJECTS)
    sections = spec_json(SECTIONS)

    plaintext = Corpus("plaintext")
    admission = Corpus("objects_admission")
    receive = Corpus("sections_receive")
    snapshot = Corpus("snapshot")

    # Shared Objects: actors of the reference corpus, in the signer order
    # of OBJECTS_PRINCIPALS (andrey, pavel, masha).
    names = ["andrey", "pavel", "masha"]
    actors = {objects["actors"][n]: i for i, n in enumerate(names)}
    so_signer = lambda c: actors.get(change_actor(c), 3) if body_of(c)[0] == 1 else 0

    chunks = []
    hex_values(objects, chunks)
    for i, c in enumerate(chunks):
        t = c[8]
        if t == 0:
            snapshot.add("so", bytes([0]) + c)
            snapshot.add("so-reframe", bytes([1]) + body_of(c)[1])
        else:
            plaintext.add("so", frame(c))
            admission.add("so-one", records([c], so_signer))
    for s in objects["scenarios"]:
        chain = [bytes.fromhex(x["change_hex"]) for x in s["changes"]]
        admission.add(s["id"], records(chain, so_signer))
        admission.add(s["id"] + "-reframe", records(chain, so_signer, reframe=True))
        plaintext.add(s["id"] + "-save", frame(bytes.fromhex(s["save_hex"])))
    for case in objects["depth"]["cases"]:
        chain = [bytes.fromhex(x["change_hex"]) for x in case["changes"]]
        admission.add(case["id"], records(chain, so_signer))
    # Negatives on their base scenario.
    scenarios = {s["id"]: s for s in objects["scenarios"]}
    for neg in objects["negatives"]:
        base = scenarios.get(neg.get("base_scenario"))
        chain = [bytes.fromhex(x["change_hex"]) for x in base["changes"]] if base else []
        seed = records(chain, so_signer) or b""
        if "plaintext_hex" in neg:
            pt = bytes.fromhex(neg["plaintext_hex"])
            seed += record(names.index(neg["signer"]), pt)
            plaintext.add(neg["id"], pt)
        elif "change" in neg:
            c = bytes.fromhex(neg["change"]["change_hex"])
            seed += record(CTL_FRAME | names.index(neg["signer"]), c)
        admission.add(neg["id"], seed)

    # §11.3 / §11.4 cases (baseline.3): the history, then the change.
    canonical = Corpus("canonical")
    for section in ("canonical", "references"):
        for case in objects.get(section, {}).get("cases", []):
            history = [bytes.fromhex(h) for h in case["history_hex"]]
            change = bytes.fromhex(case["change_hex"])
            admission.add(case["id"], records(history + [change], so_signer))
            admission.add(case["id"] + "-direct", records(history, so_signer) + record(
                CTL_FRAME | CTL_ORIGIN_ESTABLISHED, change))
            canonical.add(case["id"], bytes([0]) + change)
            if body_of(change):
                t, body = body_of(change)
                canonical.add(case["id"] + "-reframe", bytes([1, t]) + body)
    for c in chunks:
        if c[8] == 1:
            canonical.add("so", bytes([0]) + c)

    # Shared Sections: A, B, C.
    identities = sections.get("identities") or sections["fixtures"]["identities"]
    ss_actors = {a["actor_hex"]: i for i, a in enumerate(identities["actors"].values())}
    ss_signer = lambda c: ss_actors.get(change_actor(c), 3) if body_of(c)[0] == 1 else 0
    def b64(r):
        if "b64url" in r:
            t = r["b64url"]
            return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
        return base64.b64decode(r["base64"])

    for case in sections["cases"]:
        # lfcp-vector-format/1 nests the scenario under "inputs".
        inp = case.get("inputs", case)
        chain = [b64(r) for r in inp["base_changes"]]
        for branch in ("A", "B"):
            chain += [b64(r) for r in inp["branches"].get(branch, [])]
        chain += [b64(r) for r in inp.get("after_merge", [])]
        # The long-history cases (SS55: 258,162 rows) take minutes per
        # run: a receive costs O(document). Kept out of the seeds.
        cap = 64 * 1024
        receive.add(case["id"], records(chain, ss_signer), cap)
        receive.add(case["id"] + "-reframe", records(chain, ss_signer, reframe=True), cap)
        receive.add(case["id"] + "-reversed", records(chain[::-1], ss_signer), cap)
        for c in chain[-3:]:
            plaintext.add(case["id"], frame(c))
        for key in ("base_snapshot", "reference_snapshot"):
            if inp.get(key) or case.get(key):
                snapshot.add(case["id"] + "-" + key, bytes([0]) + b64(inp.get(key) or case[key]))
        if case.get("reference_snapshot_plaintext"):
            pt = b64(case["reference_snapshot_plaintext"])
            snapshot.add(case["id"] + "-plaintext", bytes([2]) + pt)
            plaintext.add(case["id"] + "-snapshot", pt)
    # The Shared Objects expansion bombs, delivered to a sections replica.
    for c in chunks:
        if c[8] != 0:
            receive.add("so-expansion", records([c], lambda _: 0))

    for corpus in (plaintext, admission, receive, snapshot, canonical):
        print(f"{corpus.dir}: {corpus.count} seeds", file=sys.stderr)


if __name__ == "__main__":
    main()
