// The sdk-ts side of the diff_ts fuzz target: a long-running process that
// reads one case per line on stdin and writes the TypeScript SDK's verdicts
// on stdout. It uses only the public npm API of sdk-ts, built locally or
// installed from npm (@openlfcp/shared-objects, its ./sections and
// ./admission entries, @openlfcp/core): the implementation is a black box
// here (independence rule).
//
// Case: {"id", "mode": "so" | "ss", "resource": hex, "principal": hex,
//        "items": [{"b64": plaintext, "signer": hex | null}]}
// Answer: {"id", "verdicts": [string per item], "heads": [string per item]}
// Verdicts: applied, duplicate, missing, held, invalid:<DIAGNOSTIC>,
// refused:<DIAGNOSTIC>, error:<CODE>.

import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { readFileSync } from "node:fs";

// Either a built sdk-ts checkout (LFCP_SDK_TS_DIR) or a directory where
// the published packages are installed (LFCP_SDK_TS_NPM, its node_modules
// resolved through each package's export map).
const dir = process.env.LFCP_SDK_TS_DIR;
const npm = process.env.LFCP_SDK_TS_NPM;
if (!dir && !npm) {
  process.stderr.write("set LFCP_SDK_TS_DIR (a built sdk-ts checkout) or LFCP_SDK_TS_NPM (an npm install)\n");
  process.exit(2);
}
const load = (pkg, sub, built) => {
  if (!npm) return import(pathToFileURL(join(dir, "packages", pkg, built)).href);
  const root = join(npm, "node_modules", "@openlfcp", pkg);
  const exports = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).exports;
  return import(pathToFileURL(join(root, exports[sub].import)).href);
};
const so = await load("shared-objects", ".", "dist/index.js");
const ss = await load("shared-objects", "./sections", "dist/sections/index.js");
const core = await load("core", ".", "dist/index.js");
const admission = await load("shared-objects", "./admission", "dist/admission/index.js");
await so.initializeAutomerge();

const bytes = (b64) => new Uint8Array(Buffer.from(b64, "base64"));
const id = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const hexHeads = (s) => (String(s).match(/[0-9a-f]{64}/g) ?? []).sort().join(",");

function failure(e) {
  if (e && typeof e.diagnostic === "string") return `invalid:${e.diagnostic}`;
  if (e && typeof e.code === "string") return e.code === "ACTOR_EQUIVOCATION" ? "held" : `error:${e.code}`;
  return `throw:${String(e && e.message ? e.message : e).slice(0, 80)}`;
}

function runObjects(c) {
  const replica = so.SharedObjectsReplica.empty({
    resource: core.resourceId(id(c.resource)),
    principal: core.principalId(id(c.principal)),
  });
  const verdicts = [];
  const heads = [];
  for (const item of c.items) {
    let v;
    try {
      const r = replica.receive(bytes(item.b64));
      v = r.status === "applied" ? "applied" : r.status === "duplicate" ? "duplicate" : "missing";
    } catch (e) {
      v = failure(e);
    }
    verdicts.push(v);
    heads.push(replica.heads().slice().sort().join(","));
  }
  return { verdicts, heads };
}

function runSections(c) {
  const replica = ss.SectionReplica.empty({
    resource: core.resourceId(id(c.resource)),
    principal: core.principalId(id(c.principal)),
  });
  const verdicts = [];
  const heads = [];
  // receiveChanges keeps nothing between calls: as a client does, the
  // units still missing a dependency are offered again with each new one.
  let waiting = [];
  for (const item of c.items) {
    let v;
    try {
      // receiveChanges takes the bare change: only the Data Unit's [1, bstr]
      // framing is removed here (no check of the change); bad framing is the
      // receiver's INVALID_AUTOMERGE_BYTES, as SOP §11 says.
      let chunk;
      try {
        chunk = so.unframeProfilePayload(bytes(item.b64));
      } catch {
        verdicts.push("refused:INVALID_AUTOMERGE_BYTES");
        heads.push(hexHeads(replica.revision()));
        continue;
      }
      let hash;
      try {
        hash = so.checkChange(chunk).hash;
      } catch (e) {
        hash = admission.refusedChangeHash(chunk, e);
      }
      const unit = { bytes: chunk, hash };
      if (item.signer) unit.signer = core.principalId(id(item.signer));
      const offered = [unit, ...waiting];
      const r = replica.receiveChanges(offered);
      const mine = r.refused.find((f) => f.index === 0);
      if (mine) v = mine.held ? "held" : `refused:${mine.diagnostic}`;
      else if (hash && r.admitted.includes(hash)) v = "applied";
      else if (hash && r.duplicates.includes(hash)) v = "duplicate";
      else if (hash && r.waiting.includes(hash)) v = "missing";
      else v = "none";
      waiting = offered.filter((u) => u.hash && r.waiting.includes(u.hash));
    } catch (e) {
      v = failure(e);
    }
    verdicts.push(v);
    heads.push(hexHeads(replica.revision()));
  }
  return { verdicts, heads };
}

const lines = createInterface({ input: process.stdin });
for await (const line of lines) {
  if (!line.trim()) continue;
  const c = JSON.parse(line);
  let out;
  try {
    out = c.mode === "ss" ? runSections(c) : runObjects(c);
  } catch (e) {
    out = { fatal: String(e && e.stack ? e.stack : e) };
  }
  process.stdout.write(JSON.stringify({ id: c.id, ...out }) + "\n");
}
