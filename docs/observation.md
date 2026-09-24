# Pluto observation pipeline (pluto.dll, CoG 2026 build)

Reverse-engineered from `release/pluto.dll` (image base 0x63f80000) with the
Ghidra decompilation in `decomp/pluto.dll.annotated.c`, checked against
`objdump -M intel` disassembly and the BWAPI 4.4.0 BW structs in `ref/bwapi`.
Constants and tables were read out of the DLL with `analysis/dllread.py`
(a small pefile helper added for this work).

Labels used below:
- **[V]** verified: read directly from decompiled or disassembled code.
- **[I]** inference: a likely reading that the code does not settle.

## 1. Call graph

| Address | Role |
|---|---|
| `63f81470` | BWAPI `onStart` thunk. Reads `player = *(int*)0x512688` (g_LocalHumanID) and `oppRace = Broodwar->enemy()->getRace()` (Game vtbl +0x118, Player vtbl +0x10), then calls `FUN_63f85f90(player, oppRace)` **[V, disasm 63f814be]** |
| `63f85f90` | onStart body. Stores `DAT_63fd2300 = player` and `DAT_63fd213c = oppRace`. Clears the selection, the control groups, the action history and the static-map cache (`DAT_63fd2638 = 0`). Sets the opponent-race one-hot (`DAT_63ff2398[race] = 1.0f` if race < 3) and the 32-float build-order bit vector `DAT_63ff2318` (the bandit-chosen build mask) **[V]** |
| `63f8baf0` | onFrame (AIModule::onFrame → jmp at 63f81440). Builds the per-frame "view" struct on the stack (`local_10c`), calls the unit enumerator, collects bullets, storms and nuke dots, then (every model step) calls the tensor builder and the shm writer **[V]** |
| `63fb3f70` | **Unit enumerator with the visibility filter** (see §3) **[V]** |
| `63fafd80` | **Tensor builder**: categorical and continuous unit rows, action masks, global vector, and a call to the spatial builder (§4–§7) **[V]** |
| `63fbb3d0` / `63fbb600` | Spatial planes, 128×128 (§6) **[V]** |
| `63fb4bc0` | Writes everything to shared memory (or to a pipe as fallback), then `SetEvent` (§8) **[V]** |
| `63faf4b0` | After each action: updates the selection set, the 10 control groups, and the 4-slot action history that the next observation reads **[V]** |

### View struct `V` (`int*`, `&local_10c` in onFrame)

| idx | content |
|---|---|
| 0 | `player` = `DAT_63fd2300` (from 0x512688) |
| 1 (byte) | **fog flag**. Hard-coded to 1: `63f8bb51: mov BYTE PTR [ebp-0x104],0x1` **[V]** |
| 2 | `Game.frameCount` (0x57F23C) |
| 3,4 | map width and height in tiles (`Game.mapTileSize` 0x57F1D4/6); maps larger than 128 abort with "Map exceeds %d tiles" |
| 5..7 | vector of 0x18-byte unit entries (from 63fb3f70) |
| 8..10 | bullets `{x, y, isStorm}` |
| 0xb..0xd | psionic storms `{x, y, 1}` |
| 0xe..0x10 | nuke dots `{x, y, alliance}` |
| 0x11..0x30 | 32 floats: build-order mask bits (copy of `DAT_63ff2318`) |
| 0x31..0x33 | opponent race one-hot Z/T/P (`DAT_63ff2398..23a0`) |
| 0x35.. | hash map unitId → {last command type, frame, ...} (the per-unit command history) |

## 2. BW memory that is read

| Address | Name | Used for |
|---|---|---|
| 0x628430 | UnitNodeList_VisibleUnit_First | main unit list and the static resource footprint |
| 0x6283EC | UnitNodeList_HiddenUnit_First | **own** units only (units in transports/buildings) |
| 0x6283F4 | UnitNodeList_ScannerSweep_First | scanner sweeps |
| 0x64DEC4 | BulletNodeTable_FirstElement | bullets and psionic storms |
| 0x59CCA8 | UnitNodeTable | unit index (`(p-0x59CCA8)/0x150`) and transport cargo lookup |
| 0x6D1260 | ActiveTileArray | visibility, explored, walkable, height, creep, occupied, cliff |
| 0x57F0F0 / 0x57F120 | Game.minerals / gas `[player]` | globals, affordability masks, **own player only** |
| 0x582144.. | Game.supplies (3 races × available/used/max) | globals, supply mask, **own only** |
| 0x58D2B0 / 0x58F2FE.. | currentUpgradeLevel SC/BW | per-unit upgrade features (indexed by the **unit's owner**, see §9) and own research masks |
| 0x58CE24 / 0x58CF44 / 0x58F140 / 0x58F230 / 0x58F3E0 / 0x58D088 | tech available/researched, research/upgrade in progress, max upgrade | action-mask predicates only (`63fb7390`, `63fba550`, `63fbadd0`, `63fbb170`), always indexed by `*V[1]` = own player **[V]** |
| 0x57F27C | Game.unitAvailability | train mask (own) |
| Game.unitCounts.completed[..][player] | tech-tree prerequisites | train/research masks (own) |
| 0x57EEE0.. | Players[] | onStart only (slot types, force; used to find the opponent / write the bandit file) |

The DLL embeds copies of the units.dat, weapons.dat, upgrades.dat and techdata.dat tables. Checked values: marine HP 40, zealot shields 60, marine build time 360, special-ability flags `0x63fd9e80` (CC = 0xc4001021), and gauss-rifle cooldown 15.

| Table | Content |
|---|---|
| `0x63fd9e80` | flags |
| `0x63fda5c0` | max HP |
| `0x63fda220` | max shields |
| `0x63fd93a0` | build time |
| `0x63fd6bc0` / `0x63fd6820` | ground / air cooldown |
| `0x63fd88c0` | cargo space |
| `0x63fd8c60` | space required |
| `0x63fd76a0` / `7de0` / `7300` / `7a40` | unit dimensions |
| `0x63fd6f60` | armor upgrade |
| `0x63fd5d40` | weapon upgrade |
| `0x63fd59a0` | energy upgrade |
| `0x63fd9ae0` / `0x63fd9740` | mineral / gas cost |

## 3. Unit selection and visibility (`FUN_63fb3f70`) [V]

It walks three BW lists and appends one 0x18-byte entry per kept unit:

```
+0x00 CUnit*   unit
+0x04 CUnit*   weaponUnit   (subUnit if its type has flag 0x10 "subunit", else unit)
+0x08 u32      id = (index+1) | uniquenessIdentifier(+0xA5) << 11
+0x0C u32      alliance: 0 = own, 1 = other player (<8), 2 = neutral (>=8)
+0x10 s16,s16  position (+0x28); if InTransport(0x40) use connectedUnit(+0x80)->position
+0x14 u8       sprite->flags(+0x0E) bit 0x20 ("hidden")
+0x15 u8       statusFlags & InTransport
+0x16 u8       detected
+0x17 u8       0
```

**List 1, visible units (0x628430).** Skipped: types ≥ 228, types with flag 0x10 (turrets and other subunits), and `orderID == 0` (Die).

- Own units (`owner == player`): always kept, `detected = 1`.
- Other players and neutrals: with the fog flag set (always), the code runs:

```c
// 63fb449a / disasm 63fb44a0..63fb44ab
if (sprite != NULL && ((sprite->visibilityFlags(+0x0C) >> player) & 1) == 0) skip;
// burrow/cloak rule, identical to BWAPI UnitUpdate.cpp:96-104
if ((statusFlags & RequiresDetection 0x100) && !((visibilityStatus(+0xE4) >> player) & 1)
    && (statusFlags & Burrowed 0x10)
    && weaponUnit->airCD(+0x56)==0 && groundCD(+0x55)==0
    && current_speed(+0x40,+0x44)==0)            skip;   // undetected, idle burrowed unit
detected = !(statusFlags & 0x100) || ((visibilityStatus >> player) & 1);
```

This matches BWAPI's `isVisible` / `isDetected` logic for a non-cheating bot, down to the "moving or attacking burrowed units are visible" exception. The one difference: an enemy unit on the visible list with `sprite == NULL` is not filtered. BWAPI would treat it as invisible. Units on the visible list normally always have sprites, so this edge probably never happens **[I]**.

**List 2, hidden units (0x6283EC).** Kept only if `owner == player`, i.e. your own units inside bunkers, transports and refineries.

**List 3, scanner sweeps (0x6283F4).** Own sweeps are always kept. An enemy sweep is kept only if at least one ActiveTile in the ±64 px box around it has `(bVisibilityFlags >> player & 1) == 0`, i.e. is currently visible. This is the same idea as BWAPI `isScannerVisible`.

**Bullets and storms (in onFrame, 63f8bc88).** From 0x64DEC4, skipped if `sprite && !(sprite->visibilityFlags & (1<<player))`. `weaponType(+0x60) == 'T'` (84, Psionic Storm) also goes to the storm list.

**Nuke dots.** Units of type Ghost, Sarah Kerrigan, Samir Duran, Alexei Stukov or Infested Duran with `orderID != 0` and `ghost.nukeDot(+0xD0) != 0` contribute a dot if the dot's sprite is visible to the player. Alliance is 0 own, 1 player < 8, 2 otherwise.

**Order and truncation (`63fafd80` head).** Rows are:
1. row 0: an all-zero "null" token;
2. the units in list order (visible list, then own hidden, then scans);
3. storm pseudo-units;
4. nuke-dot pseudo-units.

`max_units` (`this+0x2a4`) comes from the engine handshake. The protocol cap is 1024 rows (`num_units - 1 < 0x400`), and the weights use 768. When the total is too large, the pseudo-units are reserved first and real units are cut from the tail. The code logs `"WARNING: %d units truncated to %d (max_units=%d)"`. There is no sort by distance or ownership.

## 4. Per-unit categorical features (6 × int64 per row) [V]

| col | content | range |
|---|---|---|
| 0 | `unitType` (+0x64). Pseudo: 192 = nuke dot (`Unused_Terran_Marker`), 193 = psionic storm (`Unused_Protoss_Marker`) | 0..227 |
| 1 | alliance (0 own, 1 enemy, 2 neutral) → owner embedding | 0..2 |
| 2 | `orderID` (+0x4D). Undetected enemies get 23 (Nothing); pseudo-units get 23 | 0..188 |
| 3 | last command type issued by Pluto to this unit (from the action history map; 0 if none) | |
| 4 | train type. **Own only**: `buildQueue[buildQueueSlot]` (+0x98 + 2·slot), or `currentBuildUnit(+0xEC)->type`, else 228. Enemies are always 228 | 0..228 |
| 5 | research/upgrade. **Own buildings only**: order ResearchTech(75) → `techType(+0xC8)+1`; order Upgrade(76) → `upgradeType(+0xC9)+46`; else 0 | 0..106 |

## 5. Per-unit continuous features (109 floats) [V unless marked]

After filling, every value is clipped to [-5, 5] with the warning `"continuous[%d][%d] = %.3f"`.

Special types (bVar57 = true) are never actors or targets: nuke missile (14), scanner (33), scarab (85), map revealer (101), disruption web (105), the markers (192, 193) and dark swarm (202).

| k | source | normalisation |
|---|---|---|
| 0,1 | position x, y (entry +0x10/+0x12) | ×1/4096 |
| 2 | HP: `ceil(hitPoints(+0x08)/256)` | / maxHP[type] |
| 3 | shields: `ceil(shieldPoints(+0x60)/256)` | / maxShields[type] |
| 4 | energy byte (+0xA3 = energy>>8). **Own spellcasters only** | / (200, or 250 for heroes) +50 if the energy upgrade is > 0 |
| 5 | max(groundCD +0x55, airCD +0x56) of weaponUnit | / max(5, max table cooldown), clip 2 |
| 6 | spellCooldown (+0x57) | /45 |
| 7,8 | current_speed.x, .y (+0x40/+0x44) | ×(1/256)×0.25 |
| 9,10 | sin, cos(currentDirection1 +0x21 · 2π/256) | |
| 11,12 | sin, cos(weaponUnit direction) (turret) | |
| 13 | statusFlags & InAir (4) | 0/1 |
| 14 | order ∈ {Attack1, Attack2, AttackUnit, AttackFixedRange, AttackTile, AttackMove} | 0/1 |
| 15 | order ∈ {Move, Follow} | 0/1 |
| 16 | order ∈ {Stop, Guard, PlayerGuard, TurretGuard, Nothing, ComputerAI, Medic} | 0/1 |
| 17 | order == HoldPosition | 0/1 |
| 18 | frames since Pluto's last command to this unit | /240, max 1 (1 if none) |
| 19 | last command still reflected in the order. Command 5→Move, 6→AttackMove, 7→attack, repair or gather orders, 8→Stop, 9→Hold | 0/1 |
| 20 | Own: queue non-empty or `currentBuildUnit`. Enemy: `currentBuildUnit != 0` | 0/1 |
| 21 | own build progress: 1 − remainingBuildTime(+0xAC)/buildTime | |
| 22 | statusFlags & Completed | 0/1 |
| 23 | own: ≥ 2 items in the build queue | 0/1 |
| 24 | own research/upgrade progress: 1 − upgradeResearchTime(+0xC6)/time | |
| 25 | sprite hidden flag (entry +0x14) | 0/1 |
| 26 | Burrowed (0x10) | 0/1 |
| 27 | cloaked: `(statusFlags & 0x110) == 0x100` | 0/1 |
| 28 | detected (entry +0x16) | 0/1 |
| 29 | in transport (entry +0x15) | 0/1 |
| 30 | in Pluto's current selection set | 0/1 |
| 31–40 | member of Pluto's control group 1..10 | 0/1 |
| 41 | armor upgrade level of the **unit's owner** (table 0x63fd6f60) | ×0.5 |
| 42 | weapon upgrade level of the unit's owner (table 0x63fd5d40) | ×0.5 |
| 43 | Plasma Shields level of the unit's owner (units with shields) | ×0.5 |
| 44–47 | unit was an actor in action-history slot 0..3 | 0/1 |
| 48–51 | unit was the target unit of history slot 0..3 | 0/1 |
| 52 | resources (+0xD0) of resource containers, **not for alliance 1** | log1p(x)/ln 200 |
| 53–58 | stim(+0x115), ensnare(+0x116), lockdown(+0x117), stasis(+0x119), maelstrom(+0x124), plague(+0x11A) timers ≠ 0 | 0/1 |
| 59 | irradiate (+0x118) | 0/1 |
| 60 | defense matrix (+0x112) | 0/1 |
| 61 | within 48 px of a (visible) psionic storm | 0/1 |
| 62 | isBlind (+0x123) | 0/1 |
| 63 | parasiteFlags (+0x121) ≠ 0 | 0/1 |
| 64 | statusFlags SpeedUpgrade (0x10000000) | 0/1 |
| 65 | range upgrade of the unit's owner. Marine: U-238; Hydra: Grooved Spines; Dragoon: Singularity; Goliath: Charon | 0/1 |
| 66, 67 | carrying gas / minerals (resourceType +0xE0 bit 0/1) | 0/1 |
| 68 | Carrier/Gantrithor interceptors (in+out hangar) | ×0.125 |
| 69 | Reaver/Warbringer scarabs | /10 |
| 70 | Vulture/Raynor spider mines | /3 |
| 71 | **own** transport load: Σ space of loadedUnitIndex[8] | / capacity |
| 72 | unpowered: grounded building, requires psi, `DoodadStatesThing` (0x400) | 0/1 |
| 73 | under Dark Swarm (inside a swarm box grown by the unit's size) | 0/1 |
| 74 | under Disruption Web | 0/1 |
| 75 | acidSporeCount (+0x126) | (n−1)·0.0625+0.5, 0 if none |
| 76 | IsHallucination (0x40000000). **Own only** | 0/1 |
| 77–108 | Fourier position code: for i = 0..7, sin/cos(2π·x/(32·2^i)) and sin/cos(2π·y/(32·2^i)) | |

Enemy units that are visible but **not detected** (shimmering cloaked units, moving or attacking burrowed units) get masked HP/shield values: k2 = 1, k3 = 1 if the type has shields. These features are also zeroed for them: k16, k20, k53–63, k66–71 and k75, plus train-type col 4 = 228. Together with order = Nothing, this matches BWAPI's split between `canAccess` and `canAccessDetected`.

Pseudo-unit rows:
- storm: `{193, 2, 23, 0, 228, 0}`
- nuke dot: `{192, alliance, 23, 0, 228, 0}`

Their continuous rows hold only k0, k1, k18 = 1 and k77–108.

Two per-unit byte masks are also sent (`+0x79100`, `+0x79500`):
- actor mask: own, non-special, not hidden unless in transport;
- target mask: not special, not hidden, and (own/neutral or detected).

## 6. Spatial planes (`FUN_63fbb600`) [V]

The grid is a fixed 128 × 128 of build tiles (32 px), `W = H = 0x80`, with the map in the top-left corner. The DLL sends two planes; the engine string `"assembled spatial planes (bits|coords|units|count|static)"` suggests the engine itself adds the coords, units and count planes, probably from the unit rows **[I]**.

**`bits`: u16 per tile, 0x8000 bytes.** Source: `ActiveTileArray[y*W+x]`, where byte 0 is `bVisibilityFlags`, byte 1 is `bExploredFlags` (bit set = not seen) and u16 `f` is at +2.

| bit | meaning |
|---|---|
| 0x0001 | walkable (`f & 0x1`) |
| 0x0002 | buildable (`!(f & 0x80)`) |
| 0x0004, 0x0008, 0x4000 | ground-height bits (`f` 0x200, 0x400, 0x100) |
| 0x0010 | tile occupied (`f & 0x800`), **only while currently visible** |
| 0x0020 | creep (`f & 0x40`), **only while currently visible** |
| 0x0040 | explored by `player` |
| 0x0080 | currently visible to `player` |
| 0x0100–0x0800 | target position of action-history slot 0..3 |
| 0x1000 | inside a visible psionic storm (±48 px) |
| 0x2000 | a visible bullet is in this tile |
| 0x8000 | `f & 0x10` (openbw calls this `provides_cover` / doodad cover) **[I, name]** |

When the fog flag is 0 (never in this build), creep and occupancy would be shown everywhere.

**`static`: u8 per tile, 0x4000 bytes.**
- Bit 1: mineral field (176–178) or geyser (188) footprint.
- Bit 4: footprint of a building owned by neutral player 11.
- Bits 1 and 4 are computed **once per game**, on the first observation, from the visible-unit list with no visibility test. This is static neutral layout, the same data as BWAPI `getStaticNeutralUnits`.
- Bit 2: `f & 0x2000` (BWAPI calls it `bCliffEdge`, openbw `partially_walkable`).

## 7. Global features (292 floats, clipped to ±5) [V]

| idx | content |
|---|---|
| 0 | log1p(minerals[player]) / ln 200 |
| 1 | log1p(gas[player]) / ln 200 |
| 2 | (Σ_race supplies.used[player] + 1)/2 / 200 |
| 3 | Σ_race min(available, max)[player] /2 /200 |
| 4–35 | build-order bitmask (32 bits, from the bandit opening choice) |
| 36–55 | 20 action-type masks |
| 56–288 | 233 action-argument masks |
| 289–291 | opponent race one-hot Zerg/Terran/Protoss (from `enemy()->getRace()` at onStart; all zeros for Random) |

There is no explicit frame-count feature; the frame number is used only for k18.

The masks come from predicates over **own** units only (the `local_124` list is filled only for alliance 0) and **own** resources, supply, tech and upgrade state:
- `63fb7390`: can train;
- `63fbb170`: can research;
- `63fba550`: can upgrade;
- `63fbc080` / `63fbbde0` / `63fbbf30`: unload, nuke and other commands.

## 8. Shared-memory layout (`FUN_63fb4bc0`, view = `this+0x18`) [V]

| offset | content |
|---|---|
| +0x14 | error flag (set on failure) |
| +0x40 | sequence number (incremented, then `SetEvent`) |
| +0xC0 | num_units (rows incl. null row) |
| +0xC4, +0xC8 | spatial W, H (128, 128) |
| +0xCC..+0xEC | zero |
| +0x100 | categorical `int64[n][6]` (cap 0xC000 → 1024 rows) |
| +0xC100 | continuous `float[n][109]` |
| +0x79100 | actor mask `u8[n]` |
| +0x79500 | target mask `u8[n]` |
| +0x79900 | action-type mask `u8[20]` |
| +0x79940 | argument mask `u8[233]` |
| +0x79A40 | globals `float[292]` |
| +0x79F00 | spatial bits `u16[128][128]` |
| +0x81F00 | spatial static `u8[128][128]` |
| +0x85F00 | action history: 4 × int64 action type (slots at `DAT_63ff2234 + k·0x2C`) |

The pipe fallback sends the same arrays in the same order, preceded by a 0x30-byte header.

## 9. Fog of war and hidden information: verdict

**Pluto respects fog of war.** It reads StarCraft memory directly, but every read of other players' state is gated the way BWAPI gates it for a normal, non-cheating bot. Evidence:

1. **Enemy units.** Only units whose sprite `visibilityFlags` has the bot's bit are kept (`63fb44a0: movzx eax,[esi+0xc]; bt eax,edi; jb keep`). Undetected burrowed units are dropped unless they are moving or attacking. The fog flag is a constant 1 (`63f8bb51`) and `player` comes from `0x512688` at onStart.
2. **Enemy units inside transports or buildings.** Never observed: the hidden list is filtered to `owner == player`.
3. **Enemy scans, bullets, storms and nuke dots.** Only those that are visible (tile or sprite visibility).
4. **Undetected cloaked units.** HP, shields, order, status timers and cargo are masked.
5. **Map.** Creep and building occupancy appear only on currently visible tiles. Explored and visible bits are the bot's own.
6. **Enemy economy and production.** No enemy economy is read: minerals, gas, supply, unit counts, tech and upgrades-in-progress are all indexed by the bot's own player. Train type, queue, build progress, research progress, energy, cargo and hallucination are sent **only for own units**. Pluto hides enemy energy, which BWAPI would actually expose.

**Borderline items.** None of these gives more than BWAPI already would.
- Features k41–43 and k65 read upgrade levels (armor, weapon, shields, range) of a *visible* enemy unit's owner directly from `Game.currentUpgradeLevel*`. This matches BWAPI 4.4, which exposes `enemy->getUpgradeLevel(u)` whenever a completed unit using that upgrade is visible (PlayerImpl.cpp:158-176). The game UI also shows these levels.
- k64 is the unit's SpeedUpgrade status flag.
- k20 for a detected enemy is `currentBuildUnit != 0`, roughly BWAPI's `isTraining` / `getBuildUnit`, which BWAPI provides under `canAccessDetected`.
- The `static` plane's resource and neutral-building footprints are taken once at game start without a visibility test; this is public static map data.
- An enemy with a NULL sprite on the visible list would pass the filter; this is believed never to happen **[I]**.

No cheat path was found: nothing reads enemy resources, enemy production queues, enemy research in progress, or units of other players outside the visibility-filtered lists.
