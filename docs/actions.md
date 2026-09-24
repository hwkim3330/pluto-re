# Pluto action pipeline (pluto.dll, BWAPI 4.4.0 / SC:BW 1.16.1)

This document covers the path from the inference engine's answer to raw BW network command packets
in `TurnBuffer`. All addresses are pluto.dll VAs (image base 0x63f80000) unless they are StarCraft.exe
absolutes (`0x5xxxxx` / `0x6xxxxx`).

Tags:
- **[V]** verified in decompiled C or disassembly.
- **[I]** inference.

Helper scripts added for this work:
- `analysis/rd.py`: reads static tables from the DLL by VA.
- `analysis/bwenums.py`: BWAPI unit/order/tech/upgrade id to name.
- `analysis/ghidra/DecompileOne.java` and `DecompileStripped.java`: single-function re-decompile.
  Both still fail on `FUN_63fb8770` with "Forced merge caused intersection", so §6 was read from
  `objdump -M intel` disassembly.

---

## 1. Call graph

```
onFrame  FUN_63f8baf0
 ├─ (once per new frame) flush pending command queue -> TurnBuffer   (inline QueueGameCommand, §7)
 ├─ build obs  FUN_63fb3f70 / FUN_63fafd80 (incl. action masks, §5)  -> FUN_63fb4bc0 send request
 ├─ poll/wait response  FUN_63f83050  (shm @+0x85F40 or pipe, 0x28 bytes, §2)
 └─ apply  FUN_63f8a9f0(frame, a, arg, pos, u, win)
      ├─ stale-unit check against the retained observation (§4)
      ├─ FUN_63faf4b0(&DAT_63ff2100 ctrl, retained_obs, a, arg, pos, u)   -- action decoder (§3)
      │    ├─ a∈1..4  -> FUN_63fadf10  selection edit (no packets)
      │    ├─ a∈17..19 -> control-group edit (no packets)
      │    └─ else    -> FUN_63fb8770  per-unit command emitter (§6)
      │                    └─ FUN_63faf100 append packet to ctrl+0x200 byte queue
      │                    └─ FUN_63fce610 batched "select N + 1-byte cmd" (archon merges)
      ├─ flush now if the response is late (slip), else leave it for frame obs+1 (§7)
      └─ latency-probe bookkeeping (§8)
```

---

## 2. Response record (engine to DLL), 0x28 bytes [V]

Source: `FUN_63f83050`, which reads `shm+0x85F40..0x85F67` or 0x28 bytes from the stdout pipe.
Per-field consumers: `FUN_63f8a9f0` → `FUN_63faf4b0` / `FUN_63fb8770`.

| off | type | name | meaning / consumer |
|---|---|---|---|
| 0x00 | i64 | `a` | action type 0..19 (§3). `a==0` is a no-op: `FUN_63faf4b0` returns when `a==0` (both dwords). |
| 0x08 | i64 | `arg` | index into the 233-entry argument vocabulary (§3.2); 0 = none |
| 0x10 | i64 | `pos` | spatial cell: `hi = pos/256` (coarse block), `lo = pos%256` (fine cell) (§3.3) |
| 0x18 | i64 | `u` | pointer target: index into the retained observation's unit list, -1 = none |
| 0x20 | f32 | `win` | value estimate. Logged as `F%d win=%.3f`; drives the resign rule and the bandit credit. -1000.0 (`0xC47A0000`) = n/a (pipe default). |
| 0x24 | u32 | — | copied to `DAT_63fd21f8` and never read by the DLL. docs/lifecycle_ipc_bandit.md calls it the log-prob [I]. |

Pipe defaults if the read is short: `{0, 0, 0, -1, -1000.0f, 0}` (`FUN_63f83050`, locals
`local_44..local_20`).

Guard on `u` (`FUN_63f8a9f0` prologue):
- `u` is forced to -1 unless `0 ≤ u < DAT_63ff1540`.
- `DAT_63ff1540` = the number of real unit rows in the observation. It is computed in onFrame just
  before `FUN_63fb4bc0`. The pseudo-rows appended after the units (type tokens 0xC0/0xC1 for
  Disruption Web / Dark Swarm extents) cannot be pointed at.

The engine decides `a`, `arg`, `pos` and `u`. The DLL launches `pluto_infer.exe` with no arguments
(command line = quoted exe path, `FUN_63fb5420`). The engine has `--argmax` and `--seed` flags, so the
default is presumably stochastic sampling [I].

---

## 3. Action vocabulary

### 3.1 Action types `a` (20) [V]

Sources:
- the jump table at `0x63fd3eb0` / `0x63fd3f50` in `FUN_63fb8770` (index `a-5`);
- the type mask built in `FUN_63fafd80` (20 bytes, shm `0x79900`);
- the special cases in `FUN_63faf4b0`.

| a | name (derived) | arg sub-vocab | target | emitted BW packet(s) per selected unit |
|---|---|---|---|---|
| 0 | no-op | – | – | none (mask bit always 1) |
| 1 | select N nearest (replace) | 0xE3..0xE8 | unit (anchor) | none (DLL-side selection) |
| 2 | toggle N nearest (shift-click) | 0xE3..0xE8 | unit | none |
| 3 | select N nearest of anchor's type (replace) | 0xE3..0xE8 | unit | none |
| 4 | toggle N nearest of anchor's type | 0xE3..0xE8 | unit | none |
| 5 | right-click position (move/smart) | – | pos | `09 01 id` + `14 x y 0000 E400 00` (RightClick) |
| 6 | attack-move | – | pos | `09 01 id` + `15 x y 0000 E400 0E 00` (Attack, order 0x0E AttackMove) |
| 7 | right-click unit | – | unit | `09 01 id` + `14 tx ty tid ttype 00` |
| 8 | stop | – | – | `09 01 id` + `1A 00` / `1B` (CarrierStop) / `1C` (ReaverStop) |
| 9 | hold position | – | – | `09 01 id` + `2B 00` |
| 10 | train, one producer (least busy) | 0x01..0x29 | – | `09 01 id` + `1F type` / `23 type` (UnitMorph) / `27` (TrainFighter) |
| 11 | train, every selected producer | 0x01..0x29 | – | same as 10, for each capable selected unit |
| 12 | build structure | 0x2A..0x50 | pos | `09 01 id` + `0C order tx ty type` (one worker) |
| 13 | addon / building morph / research / upgrade | 0x51..0xAE | – | `0C 24 …` (PlaceAddon), `35 type`, `30 tech`, `32 upg` (one building) |
| 14 | untargeted ability | 0xAF..0xBC | – | Stim/Siege/Unsiege/Cloak/…/Cancel (§3.2) |
| 15 | position ability | 0xBD..0xCA | pos | `15 x y 0000 E400 order 00` or `0C 47 …` (Land) |
| 16 | unit-targeted ability | 0xCB..0xD8 | unit | `15 tx ty tid ttype order 00` |
| 17 | control group := selection | 0xD9..0xE2 | – | none |
| 18 | selection := control group (live members only) | 0xD9..0xE2 | – | none |
| 19 | control group += selection | 0xD9..0xE2 | – | none |

Mask bits for these types (`FUN_63fafd80`, around line 35560, `puVar36[i]`):

| bit(s) | set when |
|---|---|
| 0 | always 1 |
| 1–4, 17–19 | `local_173` (an own, commandable unit exists) |
| 5 | some selected unit can move (`FUN_63f81920`) |
| 6 | some selected unit can attack or heal (weapon tables `DAT_63fd6480` / `DAT_63fd60e0`, or Medic/Carrier/Reaver) |
| 7, 8, 9 | right-click / stop / hold capability of the selection (`local_174`, `local_195`, `local_182`) |
| 10–16 | OR of the corresponding arg-mask sub-range |

The model can only act on the DLL-side selection. Types 5–16 are masked by what the current selection
can do.

### 3.2 Argument vocabulary (233 entries, shm `0x79940`) [V]

The ranges are fixed by the mask builder (`FUN_63fafd80`) and the decoder (`FUN_63fb8770`). The
per-entry ids come from tables dumped with `analysis/rd.py` and named with `analysis/bwenums.py`.

| arg range | n | table | content | validity predicate |
|---|---|---|---|---|
| 0x00 | 1 | – | none (always 1) | – |
| 0x01–0x29 | 41 | `DAT_63fd51a0` | trainable units: Marine, Ghost, Vulture, … Nuclear_Missile, Zergling … Lurker, Probe … Dark_Templar (incl. Interceptor, Scarab) | `FUN_63fb7390` (producer/tech-tree/queue) plus minerals `DAT_63fd9ae0`, gas `DAT_63fd9740`, supply `DAT_63fd9000` (×2 for Zergling/Scourge; Lurker = 2) |
| 0x2A–0x50 | 39 | `DAT_63fd5100` | buildings: Command_Center … Bunker, Hatchery … Extractor, Nexus … Shield_Battery | `FUN_63fb7390` + minerals/gas |
| 0x51–0x5B | 11 | `DAT_63fd50c0` | addons: Comsat, Nuclear_Silo, Control_Tower, Covert_Ops, Physics_Lab, Machine_Shop; building morphs: Lair, Hive, Greater_Spire, Sunken, Spore | `FUN_63fb7390` + cost |
| 0x5C–0x7C | 33 | `DAT_63fd5020` | TechTypes: Stim_Packs … Healing (every researchable tech) | `FUN_63fbb170` + cost `DAT_63fd57e0` |
| 0x7D–0xAE | 50 | `DAT_63fd4f40` | UpgradeTypes: Terran_Infantry_Armor … Charon_Boosters | `FUN_63fba550` + `base + level·factor` cost (`DAT_63fd5560` / `DAT_63fd5460`) |
| 0xAF–0xBC | 14 | – | untargeted abilities, idx = arg-0xAF | `FUN_63fbc080(unit, idx)` |
| 0xBD–0xCA | 14 | – | position abilities, idx = arg-0xBD | `FUN_63fbbde0(unit, idx)` |
| 0xCB–0xD8 | 14 | – | unit-targeted abilities, idx = arg-0xCB | `FUN_63fbbf30(unit, idx)` |
| 0xD9–0xE2 | 10 | – | control group 1..10 (`g = arg-0xD8`) | `local_173` |
| 0xE3–0xE8 | 6 | `DAT_63fd4f18` | selection size N = {1, 2, 4, 8, 16, 0x7fffffff (all)} | always 1 |

For a trainable arg, the mask is set if any selected unit passes the predicate and resources suffice.
Minerals are read from `Game+4·p`, gas from `Game.gas`, and supply from the three race supply arrays.
The mask is resource-aware. Execution does **not** re-check cost [V: no cost test in `FUN_63fb8770`].

Untargeted abilities (a=14). Jump table `0x63fd3f18`; opcode byte = BW command.

| idx | arg | ability | packet after `09 01 id` | len |
|---|---|---|---|---|
| 0 | 0xAF | Stim (tech Stim, HP > 10) | `36` | 5 |
| 1 | 0xB0 | Siege (Tank mode, tech Siege) | `26 00` | 6 |
| 2 | 0xB1 | Unsiege | `25 00` | 6 |
| 3 | 0xB2 | Cloak (Ghost/Wraith, energy ≥ 25) | `21 00` | 6 |
| 4 | 0xB3 | Decloak | `22 00` | 6 |
| 5 | 0xB4 | Burrow | `2C 00` | 6 |
| 6 | 0xB5 | Unburrow | `2D 00` | 6 |
| 7 | 0xB6 | Lift (own x,y) | `2F x y` | 9 |
| 8 | 0xB7 | Unload all | `28 00` | 6 |
| 9 | 0xB8 | Return cargo | `1E 00` | 6 |
| 10 | 0xB9 | Archon merge (batched) | `09 n id…` + `2A` | 2n+3 |
| 11 | 0xBA | Dark Archon merge (batched) | `09 n id…` + `5A` | 2n+3 |
| 12 | 0xBB | Unload one | `29 tid`; if the selected unit is itself loaded: select its transport (`CUnit+0x80`), unload it | 7 |
| 13 | 0xBC | Cancel | `18` CancelConstruction / `19` CancelMorph / `31` CancelResearch / `33` CancelUpgrade / `34` CancelAddon / `20 FE 00` CancelTrain(slot -2) | 5–7 |

Position abilities (a=15). Order byte from `0x63fd4d78[idx]`; tech from `0x63fde8e0[idx]`, with
energy check `DAT_63fd5720[tech] ≤ CUnit+0xA3`.

| idx | ability | packet |
|---|---|---|
| 0 | Land (lifted building) | `0C 47 tx ty type`: tile = ((x-64)/32, (y-48)/32) (4×3 footprint centred on the point) |
| 1 | Scanner Sweep | `15 … 8B` |
| 2 | EMP | `15 … 7A` |
| 3 | Spider Mine | `15 … 84` |
| 4 | Nuke (Ghost + completed missile count > 0) | `15 … 80` |
| 5 | Psi Storm | `15 … 8E` |
| 6 | Recall | `15 … 89` |
| 7 | Stasis | `15 … 93` |
| 8 | Dark Swarm | `15 … 77` |
| 9 | Plague | `15 … 90` |
| 10 | Ensnare | `15 … 92` |
| 11 | Disruption Web | `15 … B5` |
| 12 | Maelstrom | `15 … BA` |
| 13 | Patrol | `15 … 98` |

Unit-targeted abilities (a=16). Order byte from `0x63fd4d68[idx]`; tech from `0x63fde920[idx]`; jump
table `0x63fd3ee0` holds the target filters. Common checks: the target must not be the caster
(`tid != own id`), and for idx 0..10 the target must not be in Stasis (`CUnit+0x119`).

| idx | ability (BW order) | target filter [V, asm @63fb97ef..63fb9c0d] |
|---|---|---|
| 0 | Yamato (0x71) | not Invincible |
| 1 | Lockdown (0x73) | Mechanical, not building/invincible |
| 2 | Irradiate (0x8F) | not building/invincible |
| 3 | Defensive Matrix (0x8D) | not building/invincible |
| 4 | Spawn Broodlings (0x79) | Organic or Mechanical; not robotic/flyer/building/invincible |
| 5 | Parasite (0x78) | not building/invincible |
| 6 | Consume (0x91) | own, Zerg, not Larva, not building |
| 7 | Mind Control (0xB6) | not own; not building/invincible/Interceptor/Mine/Larva/Egg/Cocoon/Lurker Egg |
| 8 | Feedback (0xB8) | Spellcaster, not building |
| 9 | Optical Flare (0xB9) | not building/invincible |
| 10 | Restoration (0xB4) | not building/invincible |
| 11 | Infest (0x1B) | Command Center with HP < 750 |
| 12 | Attack unit (0x0A) | not Invincible |
| 13 | Repair (0x22), SCV only | Terran mechanical, HP < max |

`num_order_types 189`, `num_train_types 229` and `num_research_types 108` are **observation**
embedding sizes (unit order ids, etc.), not the action vocabulary.

### 3.3 Spatial target (`pos`) [V]

Decode in `FUN_63faf4b0` (history x/y) and `FUN_63fb8770` @63fb8954:

```
hi = pos / 256, lo = pos % 256                 // hi: coarse block 0..63, lo: fine cell 0..255
tile_x = (hi % 8) * 16 + (lo % 16)             // 8×8 coarse grid of 16×16-tile blocks
tile_y = (hi / 8) * 16 + (lo / 16)
x = clamp(tile_x*32 + 16, 0, map_w*32 - 1)     // pixel = tile centre
y = clamp(tile_y*32 + 16, 0, map_h*32 - 1)
```

- The coarse head picks one of 8×8 = 64 blocks. The fine head picks one of 16×16 tiles inside that
  block.
- Resolution is **one build tile (32 px)** anywhere on a 128×128-tile map. Maps above 128 tiles abort
  the game (`"Map exceeds %d tiles"`).
- docs/lifecycle_ipc_bandit.md says "x = pos%256, y = pos/256". That does not match the DLL. Only the
  factorisation above is what reaches the game.

Building placement (a=12), `@63fb953a`:
- Tile = `((x - w/2)/32, (y - h/2)/32)` with pixel footprint `DAT_63fd4de0[idx] = {w,h}`, so `pos` is
  the building's centre.
- Order byte by race `DAT_63fd4da0[idx]`: 0x1E PlaceBuilding (T), 0x19 DroneStartBuild (Z),
  0x1F PlaceProtossBuilding (P), 0x24 for addon-flagged types.
- Refinery / Extractor / Assimilator: the DLL scans the observation for the `Resource_Vespene_Geyser`
  (0xBC) nearest to `(x,y)` and snaps to it. The model does not need to hit the geyser exactly.

Addon placement (a=13, idx ≤ 5): `0C 24 tx ty type` with tile `((ux+64)/32, (uy-16)/32)`, derived
from the parent building's own position.

---

## 4. Decoder state (`ctrl = DAT_63ff2100`) and validity checks [V]

`FUN_63faf4b0` / `FUN_63fadf10` / `FUN_63fb8770` keep the controller state in one struct:

| off | content |
|---|---|
| +0x000 | `unordered_set<u32 unitId>`: **current selection**, DLL-side only |
| +0x01C·g (g=1..10) | control groups, each an `unordered_set` (0x1C bytes). No size limit. |
| +0x134 + k·0x2C (k=0..3) | action history ring: `{a, selection snapshot set, target id, x, y}`. Shifted every step. Slot 0 = this step. The observation reads it (`hist[4]`). |
| +0x1E4 | `unordered_map<unitId, {a, obs_frame, x|tx, y|ty, tid}>`: last command issued to each unit ("effect" record fed into per-unit features) |
| +0x200/+0x204/+0x208 | pending command byte vector (all packets of this step, concatenated) |
| +0x20C/+0x210/+0x214 | vector<u32> of per-packet lengths |
| +0x2A4 | max_units |

Retained-observation unit row (0x18 bytes, built by `FUN_63fb3f70`):

| off | field |
|---|---|
| +0x00 | `CUnit*` |
| +0x04 | sub-unit/self |
| +0x08 | BW net id `(idx+1) \| uniq<<11` |
| +0x0C | relation: 0 own, 1 enemy, 2 neutral |
| +0x10 | x (s16), y (s16); loaded units use the transport's position |
| +0x14 | sprite-hidden bit |
| +0x15 | InTransport (status 0x40) |
| +0x16 | detected |
| +0x17 | **stale** |

Only units in BW's visible list whose sprite is visible to Pluto's player are included, and cloaked
enemies are included only if detected. There is no map-hack in the action space.

Checks done on the DLL side before any packet is written:
1. **Staleness.**
   - `FUN_63f8a9f0` rebuilds `slot → CUnit.id` from the *current* frame.
   - Every retained row whose unit died or was re-fogged since the observation gets `+0x17 = 1`. It
     is counted in the `stale_units` / `stale_max` stats.
   - A stale target gets `u = -1` (`LAB_63faf73e`), and stale units are removed from the actor list.
2. **Actor list** (`FUN_63faf4b0` → `FUN_63fb8770`): selected ids present in the observation that are
   own (`+0xC == 0`), not hidden (or loaded), and not stale.
3. **Per-unit capability.**
   - Each actor is re-tested on the *live* `CUnit` at apply time with the same predicates as the mask:
     `FUN_63fb7390` (train/build/morph), `FUN_63fbb170` (research), `FUN_63fba550` (upgrade),
     `FUN_63fbc080` / `FUN_63fbbde0` / `FUN_63fbbf30` (abilities), `FUN_63f81920` (can move), weapon
     tables (attack-move).
   - Units that fail are skipped silently, so a mixed selection only commands the units for which the
     order makes sense.
   - `FUN_63fb7390` also rejects units that are incomplete, locked down, in stasis, maelstromed or
     hallucinated, and producers whose queue is full.
4. **Target sanity**: `a ∈ {7,16}` requires a valid `u`. For a ≥ 10, `arg == 0` returns without
   acting. Abilities apply the per-spell target filters in §3.2.
5. Unit types never selectable or commandable:
   - never: Nuclear Missile, Scanner Sweep, Scarab, Map Revealer, Disruption Web, Dark Swarm and the
     marker types 0xC0/0xC1;
   - excluded from mixed selections: buildings, Larva, Egg, Cocoon, Lurker Egg, Interceptor and
     Spider Mine.

### 4.1 Selection actions (a = 1..4), `FUN_63fadf10` [V]

- The anchor is `u`. It must be own, not stale, and not one of the excluded types above.
- `N = {1,2,4,8,16,∞}[arg-0xE3]`.
- **Anchor is a building**: the selection is just the anchor.
- **Otherwise**: all own non-stale units within **128 px** of the anchor (`dx²+dy² ≤ 0x4000`) are
  candidates.
  - "Same type" (a=3/4, or an anchor that is Larva/Egg/Cocoon/Lurker Egg/Interceptor/Mine) keeps only
    the anchor's exact type.
  - Otherwise (a=1/2) buildings and those special types are excluded.
- The N nearest are kept (heap partial sort on `(dist², row, id)`).
- a=1/3 replaces the selection (`FUN_63f81a80`).
- a=2/4 is a toggle: if the anchor is already selected, the chosen units are erased; otherwise they
  are added.

There is no 12-unit cap anywhere, and N = ∞ selects every matching unit in the radius.

### 4.2 Control groups (a = 17..19), `FUN_63faf4b0` [V]

- 17: `group[g] = selection` (`FUN_63fc5fd0`).
- 18: clear the selection, then insert every member of `group[g]` that is still present, own,
  visible and not stale.
- 19: insert the selection into `group[g]`.

No BW hotkey command (0x13) is ever sent. The groups are pure DLL bookkeeping.

---

## 5. Masks shipped to the engine [V]

`FUN_63fafd80` builds two byte masks:
- `type_mask[20]`, sent to shm `0x79900`, also as floats `global[0x24..0x37]`;
- `arg_mask[233]`, sent to shm `0x79940`, also as floats `global[0x38..0x120]`.

Their content is in §3.1 / §3.2. The capability flags are computed over the **currently selected**
units in the observation. Training, building and research masks include the resource and supply test.

The engine presumably masks its action/arg logits with these masks [I]. The engine's use was not
traced.

---

## 6. Command emitter `FUN_63fb8770` (0x63fb8770–0x63fba550) [V, from disassembly]

Signature (cdecl):

```
(obs, &ctrl_closure, &actorIdx, a:i64, arg:i64, pos:i64, u:i64, ctrl)
```

1. Return for `a ∈ {0, 1..4, 17..19}`, and for an empty actor list.
2. Decode `pos` to pixel `(x, y)` (§3.3). For a ∈ {7,16} load the target's id, x, y and unit type from
   the retained row `u`.
3. **Reduce the actor list for single-producer actions:**
   - `a=10`: the capable producer with the fewest occupied build-queue slots (`63fb9ce0`).
   - `a=12`: the first selected unit able to build the structure (`63fba222`).
   - `a=13` addon/morph: the least-busy capable building (`63fba090`).
   - `a=13` research/upgrade: the capable building with the lowest busy score (`63fb8b81`).
     Busy score = 2·(currently researching/upgrading, orders 0x4B/0x4C) + queue occupancy + 1.
   - `a=11` and all other types act on **every** actor.
4. For each actor, build one packet in a stack buffer and append it with
   `FUN_63faf100(ctrl, buf, len)`:

   ```
   09 01 <id:u16>            Select(1 unit)            4 bytes
   <cmd> <payload>           the order (table in §3)
   ```

   So every unit gets its own `Select(1)` plus order. There are no multi-unit orders, except the
   archon merges: `FUN_63fce610` gathers capable templars in batches of up to 12
   into `09 n id1..idn` + `2A`/`5A`, and emits a batch only when n ≥ 2.
   - All queued flags are 0 (Pluto never shift-queues).
   - For unit-targeted Attack/RightClick, the `unitType` field carries the target's real type
     (BWAPI's own encoder writes 0xE4 there).
5. After each packet, write the per-unit effect record
   `ctrl+0x1E4[id] = {a, obs_frame, x, y, 0}` (position actions),
   `{a, obs_frame, tx, ty, tid}` (unit-target actions), or zeros.

Packet sizes (len passed to `FUN_63faf100`):
- 5: 1-byte commands;
- 6: commands with a queued/unused byte, research, upgrade;
- 7: Train, UnitMorph, CancelTrain, Unload;
- 9: Lift;
- 12: Build / Land / Addon;
- 14: RightClick;
- 15: Attack / targeted spell.

---

## 7. Flushing to BW: TurnBuffer / sendTurn [V]

The DLL inlines a byte-for-byte copy of BWAPI's `QueueGameCommand` (`ref/bwapi/.../DLLMain.cpp`) in
two places: `FUN_63f8a9f0` @5825 and `FUN_63f8baf0` @6747. For every queued packet with
`1 ≤ len ≤ 0x1FF`:

```
caps = storm#114 SNetGetProviderCaps();  max = min(caps.maxmessagesize, 512)
if (len + sgdwBytesInCmdQueue(0x654AA0) <= max)
    memcpy(TurnBuffer(0x654880) + sgdwBytesInCmdQueue, pkt, len); sgdwBytesInCmdQueue += len;
else if (gwGameMode(0x596904) != GLUES && storm#115 SNetGetTurnsInTransit(&t)
         && t < 16 - clamp(caps.callDelay,2,8 if NetMode(0x59688C) else 1))
    BWFXN_sendTurn(0x485A40)();  memcpy(...);  // start a new turn buffer
// else: packet silently dropped (same as BWAPI)
```

Afterwards both vectors are cleared.

Timing:
- **Flush point.**
  - At the top of every onFrame whose frame differs from the last one handled (`DAT_63fd2130`),
    before anything else, the pending queue is flushed.
  - In `FUN_63f8a9f0`, if the answer arrives in the observation frame F (normal case, within the 40 ms
    budget), the packets stay queued and are flushed at the start of frame **F+1**.
  - If it arrives late (frame > F, straddle/slip), they are flushed immediately in that frame, and
    `slip = arrival − (F+1)` is counted in the `slip[0..3+]` histogram.
- **Next observation**: `DAT_63ff1654 = max(flush_frame + frames_per_step − 1, F + frames_per_step)`.
  With `frames_per_step = 6` (handshake), commands always leave on the frame after the observation,
  and steps stay 6 frames apart.
- `"response with no retained observation — dropping"` (`0x63fd4acc`): a response that arrives with
  no retained observation (`DAT_63ff1650 == 0`) is discarded without decoding.
- `"free"` / `"free+hint"` / `"send"` (`0x63fd4b10`…) are build-order bandit arm names in the opening
  tables. They are unrelated to actions.

---

## 8. Action-latency probe [V]

1. **Recording** (`FUN_63f8a9f0` tail), only while the probe is unresolved (`DAT_63ff1158 == 0`) and
   frame < 240:
   - for each unit in this step's actor snapshot (history slot 0) whose effect record says it was
     commanded now,
   - and whose current BW order (`CUnit+0x4D`) is Guard/PlayerGuard (2/3, i.e. idle),
   - push `{id, flush_frame}` onto `DAT_63ff1168`.
2. **Checking** (onFrame, every frame):
   - A sample whose unit is still idle and younger than 25 frames stays pending.
   - One still idle at ≥ 25 frames is dropped.
   - Once the order changes, `latency = now − flush_frame` is recorded in `DAT_63ff115c`, and
     `"BWRL: latency sample: unit %u issued F%d applied F%d -> %d frames"` is logged.
3. **Decision**, after ≥ 8 samples or at frame 240:
   - Mode ≠ 4 → `"action latency MISMATCH: measured %d frames, trained for %d"` (the trained value is
     the constant **4**). A chat warning ("lobby turn rate / latency setting … micro will be off") and
     an event record `latency_mismatch` are written.
   - Mode = 4 → `"action latency OK"`; no samples → `"latency probe: no samples in the opening window"`.
   - The probe then stops.
4. The log says play continues "with the effect-age off". The code that disables the effect-age
   feature was not located [I]. The only verified side effects are the probe flag and the
   log/chat/event outputs.

---

## 9. Rate limits and human-impossible advantages

Verified facts:
- **One model action per step** (6 frames ≈ 0.25 s at Fastest, ~240 decisions/min).
  - Selection changes (a=1..4, 17..19) cost a whole step, so the model pays for re-selection.
  - There is no other rate limiter, APM cap or cooldown in the DLL.
- **One action fans out to N packets**, one `Select(1)+order` per selected unit.
  - The number of units is unbounded: the selection and the control groups have no 12-unit limit.
  - Per step the only limit is the turn buffer: at most 512 B per turn before an early `sendTurn`,
    and a drop only if 16−callDelay turns are in flight.
  - Example: a 40-unit attack-move is 40 × 15 B = 600 B, i.e. 80 BW "actions" (select + order) in
    one frame. Replay APM counters would show very high peaks.
- **Selection is virtual.** The model never uses the BW selection box, the screen or the camera.
  - Selection is by proximity (N nearest within 128 px of any own unit on the map).
  - Targets are one pointer over all visible units, or a tile-precise point anywhere on the map.
  - There is no screen/minimap/scroll constraint.
- **Macro conveniences no human UI offers in 1.16.1:**
  - one action trains in *every* selected producer (a=11), with no multi-building selection needed;
  - automatic choice of the least-busy producer or research building (a=10/13);
  - automatic worker choice (a=12);
  - automatic geyser snapping for gas buildings;
  - automatic addon placement;
  - Cancel picks the right cancel command.
- **Mixed-selection filtering**: every unit gets its own validated command, and incapable units are
  skipped. A human's mixed selection behaves differently.
- **Deterministic timing**: every decision is flushed exactly at obs+1 and is checked against the
  trained latency (4 frames).
- Honest limits:
  - one shared order and target per step for all actors (no per-unit different targets in a single
    step);
  - no queued/shift commands;
  - only visible or detected units can be targeted.

Inference: the effective control bandwidth is lower than a scripted bot's, because each step holds
one (type, arg, target) for the whole selection. The advantage over humans comes from unlimited group
size, perfect proximity selection without a camera, and pixel-exact tile targeting, not raw click
speed.
