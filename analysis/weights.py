#!/usr/bin/env python3
"""Parser for Pluto's weight container (pluto_weights.bin, magic "PLWB").

Layout (verified against the file and against the engine's loader,
pluto_infer.exe strings "not a Pluto weights container", "weights container:
truncated header", "weight blob: .bin size mismatch"):

    +0   char[4]  magic  "PLWB"
    +4   u32      container version (1)
    +8   u64      JSON header length L
    +16  char[L]  JSON header (UTF-8)
    pad  to a 64-byte boundary  -> data base D
    D+   raw tensor bytes; every "offset" in the header is relative to D.
         total_bytes == file_size - D.

Per-tensor header entry: name, shape, offset, nbytes, optional dtype
("float32" default / "bfloat16" / "int8"). int8 entries additionally carry
scale_offset / scale_len: a float32[scale_len] vector of per-output-channel
symmetric scales stored right after the int8 payload (w_fp32 = q * scale).
For nn.Linear-style tensors ([out, in]) and conv tensors ([out, in, kh, kw])
the scale runs over dim 0; for the custom GRU parameters stored as [in, out]
(gru.W_hq, gru.w_out_*) it runs over dim 1.

Usage:
    python3 weights.py [path/to/pluto_weights.bin] [--md out.md] [--check]
"""
import json, math, struct, sys, argparse, collections
import numpy as np

DEFAULT = str(__import__("pathlib").Path(__file__).resolve().parent.parent / "release/pluto/pluto_weights.bin")


class Tensor:
    def __init__(self, d, base):
        self.name = d["name"]
        self.shape = tuple(d["shape"])
        self.offset = d["offset"]
        self.nbytes = d["nbytes"]
        self.dtype = d.get("dtype", "float32")
        self.scale_offset = d.get("scale_offset")
        self.scale_len = d.get("scale_len")
        self.base = base

    @property
    def numel(self):
        return math.prod(self.shape)

    @property
    def scale_axis(self):
        if self.scale_len is None:
            return None
        if self.scale_len == self.shape[0]:
            return 0
        if len(self.shape) > 1 and self.scale_len == self.shape[1]:
            return 1
        return -1

    def stored_bytes(self):
        return self.nbytes + (4 * self.scale_len if self.scale_len else 0)


class Blob:
    def __init__(self, path=DEFAULT):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        magic = self.raw[:4]
        if magic != b"PLWB":
            raise ValueError("not a Pluto weights container")
        self.version, = struct.unpack_from("<I", self.raw, 4)
        hlen, = struct.unpack_from("<Q", self.raw, 8)
        self.header_len = hlen
        self.header = json.loads(self.raw[16:16 + hlen])
        self.total_bytes = self.header["total_bytes"]
        self.base = len(self.raw) - self.total_bytes
        assert self.base >= 16 + hlen and self.base % 64 == 0, self.base
        self.tensors = [Tensor(t, self.base) for t in self.header["tensors"]]
        self.by_name = {t.name: t for t in self.tensors}
        self.config = self.header["model_config"]

    def _slice(self, off, n):
        a = self.base + off
        return self.raw[a:a + n]

    def raw_array(self, name):
        t = self.by_name[name]
        b = self._slice(t.offset, t.nbytes)
        if t.dtype == "float32":
            return np.frombuffer(b, "<f4").reshape(t.shape)
        if t.dtype == "bfloat16":
            u = np.frombuffer(b, "<u2").astype(np.uint32) << 16
            return u.view("<f4").reshape(t.shape)
        if t.dtype == "int8":
            return np.frombuffer(b, "i1").reshape(t.shape)
        if t.dtype == "float16":
            return np.frombuffer(b, "<f2").astype(np.float32).reshape(t.shape)
        raise ValueError(t.dtype)

    def scales(self, name):
        t = self.by_name[name]
        if t.scale_len is None:
            return None
        return np.frombuffer(self._slice(t.scale_offset, 4 * t.scale_len), "<f4")

    def array(self, name):
        """fp32 view of a tensor (dequantized if int8)."""
        t = self.by_name[name]
        a = self.raw_array(name)
        if t.dtype != "int8":
            return a.astype(np.float32)
        s = self.scales(name)
        shp = [1] * len(t.shape)
        shp[t.scale_axis] = -1
        return a.astype(np.float32) * s.reshape(shp)

    # ------------------------------------------------------------------
    def check(self):
        """Structural checks: contiguity, bounds, scale placement."""
        spans = []
        for t in self.tensors:
            assert t.nbytes == t.numel * {"float32": 4, "bfloat16": 2, "float16": 2, "int8": 1}[t.dtype], t.name
            spans.append((t.offset, t.offset + t.nbytes, t.name))
            if t.scale_len is not None:
                assert t.scale_axis in (0, 1), t.name
                spans.append((t.scale_offset, t.scale_offset + 4 * t.scale_len, t.name + "#scale"))
        spans.sort()
        end = 0
        gaps = 0
        for a, b, n in spans:
            assert a >= end, ("overlap", n)
            gaps += a - end
            end = b
        assert end == self.total_bytes, (end, self.total_bytes)
        return gaps

    def int8_stats(self):
        """Per int8 tensor: max|q| per channel (127 => symmetric absmax quant)."""
        out = {}
        for t in self.tensors:
            if t.dtype != "int8":
                continue
            q = self.raw_array(t.name)
            ax = tuple(i for i in range(q.ndim) if i != t.scale_axis)
            m = np.abs(q.astype(np.int16)).max(axis=ax)
            out[t.name] = (int(m.min()), int(m.max()), float(self.scales(t.name).min()),
                           float(self.scales(t.name).max()))
        return out


def module_of(name):
    p = name.split(".")
    if p[0] in ("encoder",):
        return "encoder (6x pre-RMSNorm transformer)"
    if p[0] == "gru":
        if len(p) > 1 and p[1] == "slow_enc":
            return "gru.slow_enc (slow memory encoder)"
        return "gru (attention-GRU core)"
    if p[0] in ("unit_type_emb", "owner_emb", "order_emb", "last_action_emb", "train_type_emb",
                "research_type_emb", "continuous_proj", "cat_norm", "input_proj", "null_unit_enc"):
        return "unit embedding (encode_units)"
    if p[0] in ("spatial_enc", "unit_spatial_proj", "spatial_proj"):
        return "spatial encoder (+unit<->map projections)"
    if p[0] in ("encoder_norm",):
        return "encoder (6x pre-RMSNorm transformer)"
    if p[0] in ("global_proj", "action_hist_emb", "action_hist_proj"):
        return "global / action-history inputs"
    if p[0] in ("action_head", "action_cond_emb", "action_cond_mlp", "cond_norm_act"):
        return "head: action type (+cond)"
    if p[0] in ("arg_head", "arg_cond_emb", "arg_cond_mlp", "cond_norm_arg"):
        return "head: argument (+cond)"
    if p[0] in ("coarse_query_proj", "coarse_key_proj", "coarse_cond_mlp", "cond_norm_fine"):
        return "head: coarse position (8x8)"
    if p[0] in ("fine_conv_head", "fine_out"):
        return "head: fine position (FiLM conv)"
    if p[0] == "uat":
        return "head: unit-aware targeting (uat)"
    if p[0] == "target_head":
        return "head: unit pointer (target_head)"
    if p[0] == "solo_win_head":
        return "head: win value (solo_win_head)"
    return "other"


def write_md(blob, path):
    L = []
    h = blob.header
    L.append("# pluto_weights.bin — tensor table\n")
    L.append("Generated by `analysis/weights.py`. Offsets are relative to the data base "
             f"(file offset {blob.base} = 16 + JSON header {blob.header_len} B, padded to 64).\n")
    L.append(f"- label: `{h['label']}`  source: `{h['source_checkpoint']}` (weight version {h.get('source_weight_version')})")
    L.append(f"- container version {blob.version}, header dtype field `{h['dtype']}` (default for entries without `dtype`), frames_per_step {h['frames_per_step']}")
    L.append(f"- stripped (training-only) prefixes: {', '.join('`'+s+'`' for s in h['stripped_prefixes'])}")
    L.append(f"- total_bytes {blob.total_bytes:,}; file size {len(blob.raw):,}\n")
    n_by = collections.Counter(t.dtype for t in blob.tensors)
    p_by = collections.Counter()
    for t in blob.tensors:
        p_by[t.dtype] += t.numel
    tot = sum(t.numel for t in blob.tensors)
    L.append("## Summary by dtype\n")
    L.append("| dtype | tensors | params | bytes (payload+scales) |")
    L.append("|---|---:|---:|---:|")
    for d in ("int8", "bfloat16", "float32"):
        b = sum(t.stored_bytes() for t in blob.tensors if t.dtype == d)
        L.append(f"| {d} | {n_by[d]} | {p_by[d]:,} | {b:,} |")
    L.append(f"| **total** | {len(blob.tensors)} | **{tot:,}** | {sum(t.stored_bytes() for t in blob.tensors):,} |\n")
    L.append("## Parameters per module\n")
    mod = collections.OrderedDict()
    for t in blob.tensors:
        m = module_of(t.name)
        mod.setdefault(m, [0, 0])
        mod[m][0] += t.numel
        mod[m][1] += 1
    L.append("| module | tensors | params | share |")
    L.append("|---|---:|---:|---:|")
    for m, (p, n) in mod.items():
        L.append(f"| {m} | {n} | {p:,} | {100*p/tot:.1f}% |")
    L.append(f"| **total** | {len(blob.tensors)} | **{tot:,}** | 100% |\n")
    L.append("## All tensors\n")
    L.append("int8 rows: `scale` = float32 per-channel scale vector (`axis` = which dim it indexes), "
             "stored at `scale_off`; dequant `w = q * scale`.\n")
    L.append("| # | name | shape | dtype | params | offset | nbytes | scale_off | scale_len (axis) |")
    L.append("|---:|---|---|---|---:|---:|---:|---:|---|")
    for i, t in enumerate(blob.tensors):
        so = "" if t.scale_offset is None else f"{t.scale_offset}"
        sl = "" if t.scale_len is None else f"{t.scale_len} (dim {t.scale_axis})"
        L.append(f"| {i} | `{t.name}` | {list(t.shape)} | {t.dtype} | {t.numel:,} | {t.offset} | {t.nbytes} | {so} | {sl} |")
    L.append("\n## model_config (verbatim)\n")
    L.append("```json\n" + json.dumps(h["model_config"], indent=1) + "\n```\n")
    open(path, "w").write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob", nargs="?", default=DEFAULT)
    ap.add_argument("--md")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    b = Blob(a.blob)
    tot = sum(t.numel for t in b.tensors)
    print(f"{b.header['label']}: {len(b.tensors)} tensors, {tot:,} params, base {b.base}")
    if a.check:
        gaps = b.check()
        print(f"layout OK (contiguous, {gaps} padding bytes)")
        st = b.int8_stats()
        mx = collections.Counter(v[1] for v in st.values())
        mn = min(v[0] for v in st.values())
        print(f"int8 per-channel max|q|: max over tensors {dict(mx)}, min channel-max {mn}")
        for n in ("encoder.layers.0.norm1.weight", "gru.h0", "cat_norm.weight"):
            x = b.array(n)
            print(f"  {n}: mean {x.mean():.4f} std {x.std():.4f}")
    if a.md:
        write_md(b, a.md)
        print("wrote", a.md)


if __name__ == "__main__":
    main()
