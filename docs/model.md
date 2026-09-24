# Pluto (md07x02_cog2026_2578600_int8mv) — network and inference engine

Reverse-engineered from `release/pluto/pluto_weights.bin` (header + tensor shapes) and
`release/pluto/pluto_infer.exe` (Ghidra decompilation `decomp/pluto_infer.exe.c`, strings,
`objdump -M intel`). Function names below are Ghidra addresses (`FUN_1400xxxxx`).

Legend: **[V]** verified directly (tensor shape, string, or decompiled code read line by line);
**[I]** inferred (consistent with the evidence, but not read instruction-by-instruction);
**[?]** open / guessed.

Helper tools: `analysis/weights.py` (container parser, dequantiser, checks, table generator),
`analysis/fn.sh FUN_xxx` (prints one decompiled function without its declarations).
Full tensor table: `docs/weights_tensors.md`.

---

## 1. Weight container (`PLWB`) [V]

| offset | type | value |
|---|---|---|
| 0 | char[4] | `PLWB` |
| 4 | u32 | container version = 1 (engine rejects others: "weights container: unsupported version") |
| 8 | u64 | JSON header length = 55 320 |
| 16 | JSON | header (keys: format_version, dtype, byte_order, stripped_prefixes, total_bytes, source_checkpoint, source_step, source_weight_version, label, frames_per_step, model_config, tensors[269]) |
| 55 360 | bytes | data base D = 16+L rounded up to 64; `total_bytes` (320 436 560) = file size − D |

* Every tensor entry: `name, shape, offset (from D), nbytes`, optional `dtype`
  (`float32` default, `bfloat16`, `int8`; the engine also accepts `float16`).
* `int8` entries carry `scale_offset, scale_len`: a float32 vector stored immediately after the
  int8 payload. Dequantisation `w = q · s[channel]`. Scales are **symmetric per-output-channel
  absmax/127**: every one of the 133 int8 tensors has per-channel max|q| = 127 (checked by
  `weights.py --check`; a few all-zero `arg_head` rows are unused argument ids with scale 1.0).
  For `nn.Linear`/conv tensors (`[out, in(, kh, kw)]`) the scale indexes dim 0; for the custom
  GRU parameters stored `[in, out]` (`gru.W_hq`, `gru.w_out_s/u/slow`) it indexes dim 1.
* Layout is contiguous (148 alignment bytes total), no overlaps.
* dtype split: int8 133 tensors / 311.37 M params (98.8 %), bf16 22 tensors / 3.31 M
  (all conv biases of spatial_enc and fine_conv_head, `global_proj.0.weight`,
  `action_hist_proj.0.weight`, `fine_conv_head.film.bias`, `fine_conv_head.up.conv.*`,
  `fine_out.weight`, `uat.coarse_film.weight`, `uat.coarse_out.conv.weight`), fp32 114 tensors
  / 0.35 M (norm weights, embeddings, biases, `gru.h0`, null tokens).
* **Total parameters: 315 040 001** (matches the ≈315 M claim). Training-only heads were removed
  by the exporter (`stripped_prefixes`: value_head, value_win_head, value_div_head,
  opp_predict_head, unit_count_probe).

Parameters per module (from `weights.py`):

| module | params | share |
|---|---:|---:|
| unit embedding (6 embeddings, continuous_proj, cat_norm, input_proj, null_unit_enc) | 3.58 M | 1.1 % |
| spatial encoder + unit↔map projections | 9.34 M | 3.0 % |
| unit transformer encoder (6 layers) | 56.63 M | 18.0 % |
| global / action-history inputs | 1.02 M | 0.3 % |
| attention-GRU core (`gru.*` without slow_enc) | 96.62 M | 30.7 % |
| slow-memory encoder (`gru.slow_enc`) | 79.71 M | 25.3 % |
| action head + cond | 7.36 M | 2.3 % |
| arg head + cond | 2.40 M | 0.8 % |
| coarse position head (8×8) | 14.46 M | 4.6 % |
| fine position head (FiLM conv) | 6.62 M | 2.1 % |
| unit-aware targeting (uat) | 2.08 M | 0.7 % |
| unit pointer head (target_head) | 12.39 M | 3.9 % |
| win head (solo_win_head) | 22.82 M | 7.2 % |

The engine parses `model_config` into a struct (FUN at decomp line ~93348): d_model@0x68,
d_gru@0x6c, n_layers@0x70, n_heads@0x74, d_embed@0x78, d_ff_mult@0x7c, d_spatial@0x80,
c_unit@0x84, max_units@0x88, spatial_ch@0x8c, fine_ch@0x90, fine_n_convs@0x94,
gru_n_heads@0x98, gru_d_attn@0x9c, vocab sizes@0xa0–0xac, win_value_bins@0xb0,
win_value_max@0xb4, flags arch_v2/factored_fine/direct_targeting/paired_win_head/slow_memory/
bf16/coarse_locality_mask@0xb8–0xbe, frames_per_step@0xc0, slow_dim@0xc4,
slow_cache_size@0xc8, slow_period@0xcc, slow_n_heads@0xd0, slow_n_layers@0xd4 (the model object
embeds this struct at +0x328, so e.g. slow_period is read at model+0x3f4). Keys such as
`opp_predict`, `unit_aware_targeting`, `uat_*`, `pointer_head_*`, `value_head_*`,
`adjoint_clip`, `explore_floor`, `*kl*` are **not read by the engine** (training-side only);
the engine detects uat from the presence of `uat.*` tensors (flag at model+0x458) [V].
The engine refuses blobs that are not `arch_v2 + slow_memory` ("md07x era") [V].

---

## 2. One model step — overview

One decision per request; the DLL sends a request every `frames_per_step` = 6 game frames.

```
request (N units, 128x128 map, globals, masks, last 4 actions)
  │
  ├─ encode_units:  6 categorical embeddings(256 each) ─LN(1536)─┐
  │                 continuous[109] ─Linear→256─LN──────────────┴─cat(1792)─SwiGLU→768─LN   = u0 [N,768]
  ├─ unit_spatial_proj(u0) → [N,109] ─scatter-sum onto 128x128, /sqrt(count)─┐
  ├─ planes [136,128,128] = bits(16) | coords(2) | units(109) | log1p(count)(1) | static(8)
  ├─ spatial_encoder → S64 [64x64x128] (stem), S32 [32x32x128] (stage0), S8 [8x8x384] (final)
  ├─ u1 = u0 + LN(spatial_proj(gather(S32 at unit xy)));  u1[0] = null_unit_enc
  ├─ encoder: 6 × pre-RMSNorm transformer (12 heads, QK-RMSNorm, SwiGLU 3072) → RMSNorm → U [N,768]
  ├─ x_t = [LN(global_proj(g[292])), LN(action_hist_proj(emb(last 4 actions)))]  [1536]
  ├─ attention-GRU (d=4096): gates += W_i x_t + W_hq h + w_out_s·Attn(S8) + w_out_u·Attn(U)
  │                                   + w_out_slow·Attn(slow memory)          → h_t [4096]
  └─ heads (autoregressive): action(20) → arg(233) → {coarse(64) → fine(256)} | unit pointer(N)
     + win value (from the slow memory, refreshed every 8 steps)
```

Work that only depends on h_{t-1} (W_hq·h, slow-memory tick, slow K/V, the slow attention read,
the win head) is done in a **"prelude"** (FUN_14002b8d0) that runs right after the previous
response is sent (serve loop, decomp line 268600), so the per-request **critical path** is
encode → spatial → encoder → x-side GRU → heads. `--bench` times both ("N200 critical",
"N200 prelude", "N768 critical") [V].

---

## 3. Inputs at the model boundary [V]

Request = 48-byte header + payload (shared-memory offsets in §7). Engine-side struct passed to
the forward FUN_140034f10:

| field | type/shape | meaning |
|---|---|---|
| N | i32, 1 ≤ N ≤ max_units (768; protocol cap 1024) | number of unit slots |
| W, H | i32, must both be 128 | map grid ("bad request header (N=%d W=%d H=%d)") |
| flags | u32 bit0 | "forced action" present (then header bytes 0x10–0x2f = 4×i64 action, arg, pos, unit) |
| cat | i64[N,6] | per-unit ids: 0 unit_type(228), 1 owner(3), 2 order(189), 3 last_action(20), 4 train_type(229), 5 research_type(108) (column→table order read from the pointer array built at the start of FUN_140016a00) |
| cont | f32[N,109] | continuous unit features; [0]=x, [1]=y normalised to [0,1) of the 128 grid; [30] is tested `> 0.5` by the coarse locality mask [?meaning] |
| unit_mask_a | u8[N] | per-unit mask used as pointer mask for actions 1–4 and by the coarse locality mask |
| unit_mask_b | u8[N] | pointer mask for the other unit-target actions (7, 16) |
| action_mask | u8[20] | legal action types |
| arg_mask | u8[233] | legal arguments (AND-ed with a static per-action table) |
| global | f32[292] | global features |
| bits | u16[128·128] | 16 binary map planes, bit i → channel i |
| static | u8[128·128] | 8 binary static-map planes, bit i → channel 128+i |
| hist | i64[4] | last 4 action types (indices into `action_hist_emb`, 20 rows) |

Row 0 of the unit set is a reserved **null slot**: after the spatial add its embedding is
overwritten with `null_unit_enc`, and in the pointer head mask[0] is forced to 1, so "unit 0"
means "no target" [V for the code; the DLL-side filling of slot 0 is [I]].

Response (40 bytes, 5×8): i64 action, i64 arg, i64 pos, i64 unit (default −1), f32 lp, f32 win,
where `pos = coarse·256 + fine` (coarse ∈ [0,64) on the 8×8 grid, fine ∈ [0,256) = 16×16
sub-cells, i.e. one of 128×128 map cells), `lp` = joint log-probability of the sampled chain
(action + arg + coarse + fine + unit, only the heads that were used), `win` = expected outcome
∈ [−1,1] (§5.6). `--verbose` prints `step N a arg pos u lp win` per step [V].

---

## 4. Trunk

### 4.1 Unit embedding (`encode_units`, FUN_140016a00) [V]

```
e = cat(unit_type_emb[c0], owner_emb[c1], order_emb[c2], last_action_emb[c3],
        train_type_emb[c4], research_type_emb[c5])          # [N,1536]
e = LayerNorm(1536)(e)                                        # cat_norm (w+b)
c = LayerNorm(256)(Linear(109→256, bias)(cont))               # continuous_proj.0 / .1
u0 = LayerNorm(768)(SwiGLU(cat(e, c)))                         # input_proj.0 (gate_up [1536,1792],
                                                               #  down [768,768]), input_proj.1
```
SwiGLU everywhere in this model = `down(silu(g) * v)` with `[g, v] = gate_up(x)` split in halves
(gate first; "swiglu: gate_up not even"), no biases. The order "linear then LN" for
continuous_proj is from the call sequence; no activation between them was seen [I].

### 4.2 Spatial input planes [V] (main forward, decomp lines 43590–43990)

`unit_spatial_proj` ([109,768], no bias) maps u0 → 109 channels per unit. FUN_1400154b0 scatters
them into a 128×128×109 grid at `(row=int(128·y), col=int(128·x))` (clamped), summing units that
share a cell, then divides each cell by `sqrt(max(count,1))`; a count grid is kept and emitted
as `log1p(count)`. Planes are assembled channels-last, 136 per pixel, in the order given by the
engine's own description string *"assembled spatial planes (bits|coords|units|count|static)"*:

| channels | content |
|---|---|
| 0–15 | 16 bits of the u16 map word |
| 16–17 | coordinate planes (precomputed table at model+0x1348, 2 floats per cell) |
| 18–126 | 109 unit-projection channels |
| 127 | log1p(unit count) |
| 128–135 | 8 bits of the u8 static-map byte |

### 4.3 Spatial encoder (FUN_14001e8e0) [V]

All norms are per-pixel LayerNorms over channels; convs are 3×3 unless noted; "GLU" = SwiGLU on
channels, `silu(first half) * second half` (FUN_14000f950 computes `x/(1+e^-x)` on one half and
multiplies by the other).

```
stem : conv3x3 s2 p1 136→128 (+bf16 bias) → SiLU → LN(stem_norm)        128x128 → 64x64   (= S64)
stage s (s=0,1,2; C_in=128,128,256, C=128,256,384):
    h = LN(stage_norms.s)(x)
    h = GLU(conv0 3x3 s1 C_in→2C) ; h = GLU(conv1 3x3 s1 C→2C) ; h = conv2 3x3 s2 C→C
    x = h + conv3 1x1 s2 (no bias) (x)                                     64→32→16→8
    after stage 0: S32 = x   (32x32x128)
out  : S8 = LN(out_norm)(x)                                                8x8x384
```

### 4.4 Spatial→unit injection and null token [V]

`u1 = u0 + LayerNorm(768)(Linear(128→768, no bias)(S32[int(32·y), int(32·x)]))` (spatial_proj.0/.1),
then `u1[0] = null_unit_enc`.

### 4.5 Unit transformer encoder (FUN_140023940) [V]

6 layers, d=768, 12 heads × 64, pre-norm, RMSNorm (weight only):
```
a = RMSNorm(norm1)(x); q,k,v = split(wqkv(a))            # [2304,768], no bias
q = RMSNorm_64(q_norm)(q per head); k = RMSNorm_64(k_norm)(k per head)
x = x + wo(softmax(q kᵀ/√64) v)                            # full attention over all N slots
x = x + SwiGLU_3072(RMSNorm(norm2)(x))                    # ff.gate_up [6144,768], ff.down [768,3072]
U = RMSNorm(encoder_norm)(x)
```
No positional encoding (no sin/cos/RoPE code; position enters through `cont` and the spatial
gather) [I from absence]. No attention mask was observed [I].

### 4.6 Global and action-history inputs (FUN_14002be20) [V]

```
g  = LayerNorm(768)(Linear(292→768, bias, bf16 weight)(global))                 # global_proj
ah = LayerNorm(768)(Linear(1024→768, bias, bf16)(flatten(action_hist_emb[hist[0..3]])))
x_t = cat(g, ah)                                                                  # [1536]
```

### 4.7 Attention-GRU core (FUN_1400284f0 prelude part, FUN_14002be20 step part) [V]

d_gru = 4096, 8 heads, d_attn = 512 (head dim 64). Parameters:
`W_i: Linear(1536→12288, bias)`, `W_hq: [4096 → 13824]` (no bias; stored [in,out]),
`spatial_kv_proj: 384→1024`, `unit_kv_proj: 768→1024`, `slow_kv_proj: 1024→1024`,
`w_out_s / w_out_u / w_out_slow: [512 → 12288]` (stored [in,out]), `h0[4096]`.

```
hq = h_{t-1} @ W_hq                     # [13824] = [hr | hz | hn | q_s | q_u | q_slow]  (4096·3 + 512·3)
xi = W_i(x_t)                           # [12288] = [xr | xz | xn]
K_s,V_s  = split(spatial_kv_proj(S8 tokens [64,384]))       # 64 coarse cells
K_u,V_u  = split(unit_kv_proj(U [N,768]))
K_sl,V_sl= split(slow_kv_proj(M [128,1024]))                # slow memory, see 4.8 (prelude)
a_s  = w_out_s   @ MHA(q_s,  K_s,  V_s)        # each [12288]
a_u  = w_out_u   @ MHA(q_u,  K_u,  V_u)
a_sl = w_out_slow@ MHA(q_slow,K_sl,V_sl)       # computed in the prelude
r = σ(xr + hr + a_s[r] + a_u[r] + a_sl[r])
z = σ(xz + hz + a_s[z] + a_u[z] + a_sl[z])
n = tanh(xn + r ⊙ hn + a_s[n] + a_u[n] + a_sl[n])
h_t = (1 − z) ⊙ n + z ⊙ h_{t-1}
```
The attention reads are queried from **h_{t-1}** (not from x_t) and enter all three gates
additively, outside the reset-gate product — read directly from the gate loop at the end of
FUN_14002be20. `h` is reset to `gru.h0` at game start (FUN_140010400).

### 4.8 Slow memory (FUN_140010400 init, FUN_140028900 tick, FUN_14001a780 read) [V except where noted]

State: `cache[L=4][128][1024]`, initialised with `cache[l][*] = slow_enc.null_token[l]`.
Every `slow_period`=8 steps (counter `step % 8 == 0`, tick happens in the prelude, before the
step that uses it):
```
x = in_proj(RMSNorm_4096(in_norm)(h_{t-1}))            # 4096 → 1024
for l in 0..3:
    a  = RMSNorm(norm_input)(x)
    kv = cat(kv_cache(RMSNorm(norm_cache)(cache[l][1:128])),   # 127 oldest-dropped entries
             kv_input(a))                                       # + the current token  → 128 keys
    x  = x + out_proj(MHA_8x128(q_proj(a), kv))
    x  = x + SwiGLU_4096(RMSNorm(ff_norm)(x))
    cache[l] = cache[l][1:] ++ [x]                               # FIFO of layer-l outputs  [I: which tensor is appended]
M = cache[3]            # [128,1024] → slow_kv_proj → keys/values for the GRU's slow read
win_in = cache[3][-1]   # newest top-layer output → solo_win_head
```
So the recurrent core has a 4-layer transformer memory over the last 128 ticks × 8 steps × 6
frames = 6 144 frames (≈4.3 min of game time at fastest speed). The slow K/V and the win head
are recomputed only when the cache changes (flag at model+4000) [V].

---

## 5. Heads and the autoregressive chain (main forward FUN_140034f10) [V]

A single action tuple is produced per step. Static action-space tables are built at load by
FUN_14001d460 [V]: `needs_pos[a]` = {5, 6, 12, 15}; `needs_unit[a]` = {1, 2, 3, 4, 7, 16};
`needs_arg[a]` = {1–4, 10–19}; pointer mask = unit_mask_a for a ∈ {1–4}, else unit_mask_b;
plus a 20×233 table of arguments allowed per action (AND-ed with the request's arg_mask).
Semantics of the ids are not in the engine (`--prof-action move|rclick` exists for profiling).
`pos` is used only when the action needs a position and not a unit.

All distributions are masked log-softmaxes computed in double precision; masked entries are
excluded (FUN_1400098a0 / inline code).

### 5.1 Action type
`logits = action_head(h_t)` ([20,4096], no bias), mask, sample `a`.

### 5.2 Action conditioning
`c_act = RMSNorm(cond_norm_act)(SwiGLU_768(cat(h_t, action_cond_emb[a])))` — action_cond_mlp
gate_up [1536, 4352=4096+256], down [768,768].

### 5.3 Argument (if needs_arg[a])
`logits = arg_head(c_act)` ([233,768]); mask = arg_mask ∧ table[a]; sample `arg`.
`c_arg = RMSNorm(cond_norm_arg)(SwiGLU_768(cat(c_act, arg_cond_emb[arg])))` (gate_up [1536,1024]).
If the action has no arg, `c_arg` is not computed and later heads take `c_act` [I: the code keeps
one "current cond" pointer that is only advanced when the arg head runs].

### 5.4 Position: coarse → fine (if needs_pos)
*ResMLP* (FUN_140018940, used by coarse/target query/key projections and the win head):
```
y = in_proj(x)                                  # no bias
for i in 0..2: y = y + SwiGLU_i(RMSNorm(norms.i)(y))   # blocks.i.gate_up / down
out = out_proj(RMSNorm(final_norm)(y))
```
Coarse (8×8 = 64 cells, one per S8 token):
```
Kc = coarse_key_proj(S8 tokens)         # ResMLP 384→768→384, [64,384] (computed only if needed)
qc = coarse_query_proj(c_arg)           # ResMLP 768→384
logit_c = Kc·qc / √384
+ uat coarse logits (below)
mask   = coarse locality mask (8x8, built from units flagged in unit_mask_a whose cont[30] > 0.5,
         dilated by one cell; cells holding any unit are also tracked)   [V code, semantics ?]
sample coarse cell kc
```
Unit-aware targeting (uat, present in this blob) [V]:
```
f  = uat.unit_proj(U)                               # 768→128, per unit
G8 = scatter(f → 8x8 grid by unit xy)               # FUN_140015fa0(...,8)
z  = GLU(uat.coarse_in conv3x3 (cat(S8, G8): 512 → 256))            # → 128 ch
z  = z + GLU(conv(LN(z)))  ×2                        # uat.coarse_norms/convs (3x3, 256 out → 128)
γ,β = uat.coarse_film(c_arg) (768→256, bf16);  z = (1+γ)·z + β
logit_c += uat.coarse_out conv3x3 (128→1)(z)         # "act.uat.coarse_add"
G64 = scatter(f → 64x64 grid); S64' = S64 + uat.fine_in(G64)   # 128→128, "act.uat.fine_corr"
```
Fine conditioning: `c_fine = RMSNorm(cond_norm_fine)(SwiGLU_768(cat(c_arg, Kc[kc])))` —
coarse_cond_mlp gate_up [1536, 1152 = 768+384] [I: the 384-vector is the chosen coarse key].

Fine head (factored, FUN_140020220) — runs only on a 16×16 crop of S64' centred on the chosen
coarse cell (coarse cell = 8×8 block of the 64-grid, halo = fine_n_convs+1 = 4, zero padded):
```
y = GLU(proj conv3x3 p0 128→512)            # 16→14, 256 ch
for i in 0..2: y = crop(y) + GLU(convs.i conv3x3 p0 (LN(norms.i)(y)))   # 14→12→10→8   [I: residual crop]
γ,β = fine_conv_head.film(c_fine) (768→512, bias); y = (1+tanh(γ))·y + β
y = GLU(up: ConvTranspose2d 256→512, k4 s2 (bf16, widened to fp32))       # 8x8 → 16x16, 256 ch
logit_f = fine_out(y) (1x1, 256→1)          # 256 logits  → sample fine sub-cell kf
pos = kc*256 + kf
```

### 5.5 Unit pointer (if needs_unit[a])
```
Kt = target_head.key_proj(U)        # ResMLP 768→384 over all N slots
qt = target_head.query_proj(c_arg)  # ResMLP 768→384
logit_u = Kt·qt / √384 ; mask = (unit_mask_a if a∈1..4 else unit_mask_b), mask[0] = 1 (null)
sample u
```

### 5.6 Win value [V]
`o = solo_win_head(cache[3][-1])` — ResMLP 1024→1536 (3 blocks, SwiGLU 1536) → 4 logits.
The engine reports `win = Σ softmax(o)·[+1, −1, 0, 0]`, i.e. P(class0) − P(class1)
(constants 1.0 / −1.0 / 0 read from .rdata 0x14015b310 / 0x14015b598) [V]; class meaning
(win / loss / draw / other) is [I]. The 53-bin categorical `win_value_*` heads of the config
and the paired/opponent heads were stripped; `paired_win_head=true` in the config therefore has
no counterpart in the shipped blob. Because the input is the slow memory, `win` changes only
every 8 steps. The DLL resigns on a sustained pinned-loss estimate (README).

### 5.7 Sampling [V] (FUN_1400349f0)
* PRNG: `std::mt19937_64` (tempering masks 0x5555555555555555 / 0x71d67fffeda60000 /
  0xfff7eee000000000, 312-word state, init multiplier 0x5851f42d4c957f2d).
* Seed: `--seed <u64>`; otherwise `std::random_device("default")` (32-bit value); printed in the
  "ready" log line.
* Draw `u ∈ [0,1)` (53-bit, clamped below 1), walk the cumulative sum of `exp(logp_i)`, return
  the first index with cumsum > u; fall back to argmax. **Temperature 1, no top-k/nucleus**.
* `--argmax` → greedy for every head.
* If the request carries a forced action (flag bit0), each head uses the forced index instead of
  sampling but still runs the network and accumulates the log-probabilities (teacher-forced
  chain) [V code; the DLL's use of it is [I], e.g. scripted/bandit openings].
* "Thompson" appears only in `pluto.dll` ("next-pick probabilities … %d Thompson draws"): the
  opening bandit samples build orders by Thompson sampling over per-opponent win/loss counts;
  it is not part of the network's sampling.

Per step the model therefore emits exactly **one** action: `(action ∈ 20, arg ∈ 233 | –,
target = map cell ∈ 128×128 | unit slot ∈ N | –)`. There is no separate "selected units" head;
which unit(s) execute the action must be decided by the argument/target semantics or by the DLL
[?].

---

## 6. PyTorch-style reconstruction (loads the blob's names/shapes)

```python
import torch, torch.nn as nn, torch.nn.functional as F

class RMSNorm(nn.Module):
    def __init__(s, d, eps=1e-6): super().__init__(); s.weight = nn.Parameter(torch.ones(d)); s.eps = eps
    def forward(s, x): return x * torch.rsqrt(x.pow(2).mean(-1, keepdim=True) + s.eps) * s.weight

class SwiGLU(nn.Module):               # {prefix}.gate_up.weight [2H,in], {prefix}.down.weight [out,H]
    def __init__(s, d_in, hidden, d_out):
        super().__init__(); s.gate_up = nn.Linear(d_in, 2*hidden, bias=False); s.down = nn.Linear(hidden, d_out, bias=False)
    def forward(s, x): g, v = s.gate_up(x).chunk(2, -1); return s.down(F.silu(g) * v)

class ResMLP(nn.Module):               # coarse_*_proj, target_head.*_proj, solo_win_head
    def __init__(s, d_in, d, d_out, n=3):
        super().__init__(); s.in_proj = nn.Linear(d_in, d, bias=False)
        s.norms = nn.ModuleList(RMSNorm(d) for _ in range(n)); s.blocks = nn.ModuleList(SwiGLU(d, d, d) for _ in range(n))
        s.final_norm = RMSNorm(d); s.out_proj = nn.Linear(d, d_out, bias=False)
    def forward(s, x):
        y = s.in_proj(x)
        for nrm, blk in zip(s.norms, s.blocks): y = y + blk(nrm(y))
        return s.out_proj(s.final_norm(y))

class Conv(nn.Module):                 # "{p}.conv.weight/bias"
    def __init__(s, ci, co, k=3, st=1, p=1, bias=True): super().__init__(); s.conv = nn.Conv2d(ci, co, k, st, p, bias=bias)
    def forward(s, x): return s.conv(x)
def glu(x): a, b = x.chunk(2, 1); return F.silu(a) * b
class LN2d(nn.LayerNorm):              # channel LayerNorm on NCHW
    def forward(s, x): return super().forward(x.permute(0,2,3,1)).permute(0,3,1,2)

class SpatialEncoder(nn.Module):
    def __init__(s):
        super().__init__()
        s.stem = Conv(136, 128, 3, 2, 1); s.stem_norm = LN2d(128)
        cin, cs = [128, 128, 256], [128, 256, 384]
        s.stages = nn.ModuleList(nn.ModuleList([Conv(ci, 2*c), Conv(c, 2*c), Conv(c, c, 3, 2, 1),
                                                Conv(ci, c, 1, 2, 0, bias=False)]) for ci, c in zip(cin, cs))
        s.stage_norms = nn.ModuleList(LN2d(ci) for ci in cin); s.out_norm = LN2d(384)
    def forward(s, planes):                          # [B,136,128,128]
        x = s.stem_norm(F.silu(s.stem(planes))); s64 = x
        for i, (st, nrm) in enumerate(zip(s.stages, s.stage_norms)):
            h = glu(st[0](nrm(x))); h = glu(st[1](h)); x = st[2](h) + st[3](x)
            if i == 0: s32 = x
        return s64, s32, s.out_norm(x)               # 64x64x128, 32x32x128, 8x8x384

class EncLayer(nn.Module):
    def __init__(s, d=768, h=12):
        super().__init__(); s.h = h
        s.norm1, s.norm2 = RMSNorm(d), RMSNorm(d); s.q_norm, s.k_norm = RMSNorm(d//h), RMSNorm(d//h)
        s.wqkv = nn.Linear(d, 3*d, bias=False); s.wo = nn.Linear(d, d, bias=False); s.ff = SwiGLU(d, 4*d, d)
    def forward(s, x):                               # [N,768]
        q, k, v = s.wqkv(s.norm1(x)).view(x.shape[0], 3, s.h, -1).unbind(1)
        q, k = s.q_norm(q), s.k_norm(k)
        a = F.scaled_dot_product_attention(q.transpose(0,1), k.transpose(0,1), v.transpose(0,1))
        x = x + s.wo(a.transpose(0,1).reshape(x.shape))
        return x + s.ff(s.norm2(x))

def mha(q, K, V, heads):                             # q [D], K,V [T,D]
    T, D = K.shape; hd = D // heads
    return F.scaled_dot_product_attention(q.view(heads, 1, hd), K.view(T, heads, hd).transpose(0,1),
                                          V.view(T, heads, hd).transpose(0,1)).reshape(D)

class SlowLayer(nn.Module):
    def __init__(s, d=1024, heads=8):
        super().__init__(); s.heads = heads
        s.norm_input, s.norm_cache, s.ff_norm = RMSNorm(d), RMSNorm(d), RMSNorm(d)
        s.q_proj = nn.Linear(d, d, bias=False); s.kv_input = nn.Linear(d, 2*d, bias=False)
        s.kv_cache = nn.Linear(d, 2*d, bias=False); s.out_proj = nn.Linear(d, d, bias=False); s.ff = SwiGLU(d, 4*d, d)
    def forward(s, x, cache):                        # x [1024], cache [128,1024]
        a = s.norm_input(x)
        kv = torch.cat([s.kv_cache(s.norm_cache(cache[1:])), s.kv_input(a)[None]], 0)
        K, V = kv.chunk(2, -1)
        x = x + s.out_proj(mha(s.q_proj(a), K, V, s.heads))
        return x + s.ff(s.ff_norm(x))

class SlowEnc(nn.Module):
    def __init__(s):
        super().__init__(); s.null_token = nn.Parameter(torch.zeros(4, 1024))
        s.in_norm = RMSNorm(4096); s.in_proj = nn.Linear(4096, 1024, bias=False)
        s.layers = nn.ModuleList(SlowLayer() for _ in range(4))
    def init_cache(s): return s.null_token[:, None, :].expand(4, 128, 1024).clone()
    def tick(s, h, cache):
        x = s.in_proj(s.in_norm(h)); new = []
        for l, layer in enumerate(s.layers):
            x = layer(x, cache[l]); new.append(torch.cat([cache[l][1:], x[None]], 0))
        return torch.stack(new)

class AttnGRU(nn.Module):
    def __init__(s, d=4096, da=512, heads=8):
        super().__init__(); s.d, s.da, s.heads = d, da, heads
        s.W_i = nn.Linear(1536, 3*d)                             # gru.W_i.weight/bias
        s.W_hq = nn.Parameter(torch.zeros(d, 3*d + 3*da))        # [in,out]
        s.w_out_s, s.w_out_u, s.w_out_slow = (nn.Parameter(torch.zeros(da, 3*d)) for _ in range(3))
        s.h0 = nn.Parameter(torch.zeros(d))
        s.spatial_kv_proj = nn.Linear(384, 2*da, bias=False); s.unit_kv_proj = nn.Linear(768, 2*da, bias=False)
        s.slow_kv_proj = nn.Linear(1024, 2*da, bias=False); s.slow_enc = SlowEnc()
    def forward(s, x, h, S8tok, U, M):
        d, da = s.d, s.da
        hq = h @ s.W_hq; hr, hz, hn = hq[:3*d].chunk(3); qs, qu, qsl = hq[3*d:].chunk(3)
        xr, xz, xn = s.W_i(x).chunk(3)
        att = 0
        for q, src, proj, wout in ((qs, S8tok, s.spatial_kv_proj, s.w_out_s), (qu, U, s.unit_kv_proj, s.w_out_u),
                                   (qsl, M, s.slow_kv_proj, s.w_out_slow)):
            K, V = proj(src).chunk(2, -1); att = att + mha(q, K, V, s.heads) @ wout
        ar, az, an = att.chunk(3)
        r = torch.sigmoid(xr + hr + ar); z = torch.sigmoid(xz + hz + az)
        n = torch.tanh(xn + r * hn + an)
        return (1 - z) * n + z * h

class Pluto(nn.Module):
    def __init__(s):
        super().__init__()
        s.null_unit_enc = nn.Parameter(torch.zeros(768))
        s.unit_type_emb = nn.Embedding(228, 256); s.owner_emb = nn.Embedding(3, 256); s.order_emb = nn.Embedding(189, 256)
        s.last_action_emb = nn.Embedding(20, 256); s.train_type_emb = nn.Embedding(229, 256); s.research_type_emb = nn.Embedding(108, 256)
        s.continuous_proj = nn.Sequential(nn.Linear(109, 256), nn.LayerNorm(256)); s.cat_norm = nn.LayerNorm(1536)
        s.input_proj = nn.Sequential(SwiGLU(1792, 768, 768), nn.LayerNorm(768))
        s.unit_spatial_proj = nn.Linear(768, 109, bias=False)
        s.spatial_enc = SpatialEncoder()
        s.spatial_proj = nn.Sequential(nn.Linear(128, 768, bias=False), nn.LayerNorm(768))
        s.encoder = nn.Module(); s.encoder.layers = nn.ModuleList(EncLayer() for _ in range(6)); s.encoder_norm = RMSNorm(768)
        s.global_proj = nn.Sequential(nn.Linear(292, 768), nn.LayerNorm(768))
        s.action_hist_emb = nn.Embedding(20, 256); s.action_hist_proj = nn.Sequential(nn.Linear(1024, 768), nn.LayerNorm(768))
        s.gru = AttnGRU()
        s.action_head = nn.Linear(4096, 20, bias=False); s.action_cond_emb = nn.Embedding(20, 256)
        s.action_cond_mlp = SwiGLU(4352, 768, 768); s.cond_norm_act = RMSNorm(768)
        s.arg_head = nn.Linear(768, 233, bias=False); s.arg_cond_emb = nn.Embedding(233, 256)
        s.arg_cond_mlp = SwiGLU(1024, 768, 768); s.cond_norm_arg = RMSNorm(768)
        s.coarse_query_proj = ResMLP(768, 768, 384); s.coarse_key_proj = ResMLP(384, 768, 384)
        s.coarse_cond_mlp = SwiGLU(1152, 768, 768); s.cond_norm_fine = RMSNorm(768)
        s.fine_conv_head = FineConvHead()           # proj Conv(128,512,3,1,0); convs[3] Conv(256,512,3,1,0); norms[3] LN2d(256)
                                                    # film Linear(768,512); up ConvTranspose2d(256,512,4,2,1)
        s.fine_out = nn.Linear(256, 1, bias=False)
        s.uat = UAT()                               # unit_proj Linear(768,128,no bias); coarse_in Conv(512,256);
                                                    # coarse_convs[2] Conv(128,256); coarse_norms[2] LN2d(128);
                                                    # coarse_film Linear(768,256); coarse_out Conv(128,1); fine_in Linear(128,128,no bias)
        s.target_head = nn.Module(); s.target_head.query_proj = ResMLP(768, 768, 384); s.target_head.key_proj = ResMLP(768, 768, 384)
        s.solo_win_head = ResMLP(1024, 1536, 4)
```
`load_state_dict` works on the dequantised tensors from `weights.py` (`Blob.array(name)`),
with two transposes: `gru.W_hq`/`gru.w_out_*` are used as `x @ W` (stored `[in,out]`), and the
Sequential/SwiGLU wrappers need the obvious key remapping (`continuous_proj.0/.1`,
`input_proj.0.gate_up`, `spatial_enc.stages.s.k.conv`, …) — names in the blob already follow
this structure. `FineConvHead`/`UAT` forward passes are as written in §5.4.

---

## 7. Inference engine (`pluto_infer.exe`)

### 7.1 Process, transport, protocol [V]
* 64-bit MinGW exe launched by the 32-bit `pluto.dll`; exits if the parent dies
  ("parent process exited", WaitForMultipleObjects on {request event, parent handle}).
* Transport: shared memory + events when the env vars `PLUTO_SHM_SEC`, `PLUTO_SHM_REQ_EV`,
  `PLUTO_SHM_RESP_EV`, `PLUTO_SHM_PARENT` (inherited handles) are present and the header
  matches: magic `0x4d534c50` ("PLSM"), version 3, size 0x85f80 (548 736 B), max units 1024;
  otherwise stdin/stdout pipes (same byte layout, 48-byte header then the arrays, 40-byte response).
* Shared-memory layout (byte offsets): 0x00 magic, 0x04 version, 0x08 size, 0x0c max_units,
  0x10 ack magic written by the engine, 0x14 quit flag, 0x40 request sequence, 0x80 response
  sequence, 0xc0 request header (48 B), 0x100 cat i64[1024·6], 0xc100 cont f32[1024·109],
  0x79100 unit_mask_a u8[1024], 0x79500 unit_mask_b u8[1024], 0x79900 action_mask u8[20],
  0x79940 arg_mask u8[233], 0x79a40 global f32[292], 0x79f00 bits u16[16384],
  0x81f00 static u8[16384], 0x85f00 hist i64[4], 0x85f40 response (40 B).
* Loop: wait for req-seq change → copy → forward → write response, bump resp-seq, SetEvent →
  run the prelude for the next step.

### 7.2 Command line and configuration [V]
`--blob <path>` (default `pluto_weights.bin` next to the exe), `--backend pk|int8|int8mv`,
`--threads N`, `--bench`, `--seed <u64>`, `--argmax`, `--log <file>`, `--verbose`,
`--ptx <x>` (ignored; leftover of the CUDA build), `--prof N`, `--prof-secs`, `--prof-gap`,
`--prof-ready <file>`, `--prof-action move|rclick`.
`pluto/pluto_config.json` (written by `--bench`) supplies `backend` and `threads`; file format:
```json
{ "backend": "int8mv", "threads": T, "model_version": 2578600, "model_label": "...",
  "vnni": true|false, "hw_threads": H,
  "bench": [ {"backend": ..., "threads": t, "n200_critical_ms": .., "n200_prelude_ms": ..,
              "n768_critical_ms": .., "rss_mb": ..}, ... ] }
```
`--bench` loads the blob, sweeps a thread list derived from the hardware thread count
(min(4,H), min(6,H), min(8,H), H, … deduplicated), times a 200-unit critical step, the 200-unit
prelude and a 768-unit critical step, records peak RSS, chooses the thread count with the best
N200-critical time, and writes the file. With an int8 blob the backend is fixed to `int8mv`
("int8 blob: backend fixed to int8mv, sweeping threads only").
Env vars: `BWRL_ENGINE_THREADS`, `BWRL_INT8` (`0` → backend `pk`), `BWRL_INT8_MATVEC` (`0` →
`int8`), `BWRL_NO_VNNI`, `BWRL_KEEP_AFFINITY`, `BWRL_NO_POOL`, `BWRL_POOL_NOALIGN`,
`BWRL_GEMM_TASKS_MULT`, `BWRL_GEMM_DYN`, `BWRL_PACK_ARES`, `BWRL_PACK_GROUP`, `BWRL_I8_NOSHARE`,
`BWRL_I8_NOFUSE`, `BWRL_I8_DUMP` (dumps `c%04d_M_K_N` a/q/s/zp tensors), `BWRL_DUMP_RESID`
(per-activation hashes, the `act.*` tags).

### 7.3 Quantisation and kernels
* **Weights [V]:** int8 blob → "int8 blob carries s8 weights only … backend must be int8mv";
  tensors are used pre-quantised ("int8 blob: %d tensors loaded pre-quantized"), symmetric s8
  with fp32 per-output-channel scales. For M=1 products (GRU, heads, slow encoder, single-token
  MLPs) they are laid out as **row-dot** matrices (rows padded to 32 bytes; "fill_rowdot_i8",
  "linear: i8-rowdot weight requires M == 1"); for M>1 (unit encoder over N tokens, spatial
  convs via `conv2d/im2col_q8`, key projections) they are packed into GEMM panels
  ("fill_pack_b_i8", "quantize_pack_b"). bf16 tensors stay bf16-resident for M=1 matvecs
  (global_proj, action_hist_proj, uat.coarse_film) or are widened to fp32 at load (conv biases,
  the transposed conv, "repack: transpose conv must be fp32-resident"). fp16 blob entries would
  be widened at load.
* **Activations [V]:** quantised on the fly, **asymmetric u8 per row/vector**: min/max scan →
  scale = (max−min)/255 with min ≤ 0 ≤ max, zero-point → u8 (FUN_140082cd0, `_zp.bin` in the
  dump names). The same quantised activation is shared across GEMMs that read the same tensor
  (e.g. `U` for unit_kv_proj, target_head.key_proj, uat.unit_proj; cache at model+0x1360 /
  +0x13c0; disabled by `BWRL_I8_NOSHARE`).
* **Dot products [V]:** u8×s8 → s32. With AVX-VNNI (CPUID.7:EAX bit 4, VEX-encoded
  `{vex} vpdpbusd ymm`, 86 occurrences; hand-unrolled 4-accumulator row-dot kernel at
  0x140083840) or the **"AVX2 madd fallback"**: u8 split into even/odd bytes (`vpand 0x00ff`,
  `vpsrlw 8`), s8 sign-extended (`vpsllw/vpsraw 8`), `vpmaddwd` accumulate. Result
  `y = s_w[j]·s_x·(Σ q_w q_x − zp·Σ q_w)` (zero-point correction via row sums) [I for the exact
  correction formula]. No AVX-512 (no zmm in the binary). Requires AVX2+FMA
  ("this CPU lacks AVX2/FMA … cannot run").
* Non-GEMM math is fp32 (norms, softmax, SiLU with a polynomial exp, tanh via libm); head
  log-softmaxes and sampling are in double.
* An OpenBLAS copy is linked (SGEMM/SGEMV strings) for the fp32 "pk"/native paths; not used by
  this int8 blob [I].

### 7.4 Threading [V]
Custom thread pool (futex-style `WakeByAddressAll`), default ≤ 6 threads (README) unless
`--threads`, `BWRL_ENGINE_THREADS` or `pluto_config.json` say otherwise. Kernels split rows
across the pool only when `M·K ≥ 30000` and the pool has ≥ 2 threads; otherwise they run inline.
At start the engine widens its CPU affinity from the mask inherited from StarCraft to the full
system mask ("affinity expanded %u -> %u cpus (inherited mask …, pinned parent, e.g.
StarCraft)"), unless `BWRL_KEEP_AFFINITY` is set. Profiling scopes (`encode_units`,
`spatial_encoder`, `encoder`, `slow_tick`, `gru_step`, `heads/*`, `enc/*`, `sdpa/*`,
`conv2d/*`, `prelude`) feed the `--prof` report.

---

## 8. Open points
* Semantics of the 20 action ids / 233 argument ids and of the per-unit masks (belongs to the
  DLL side); the engine only has the static tables in §5.
* Exact tensor appended to each slow-cache layer (layer output assumed) and whether the fine
  conv blocks add a cropped residual — inferred from call order, not traced instruction by
  instruction.
* Meaning of the 4 win-head classes (only the ±1 weighting is certain).
* `direct_targeting` is parsed but its effect was not located.
