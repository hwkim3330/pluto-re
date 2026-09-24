# pluto-re

Reverse-engineering notes on **Pluto**, tscmoo's StarCraft: Brood War AI
(release `cog2026-2578600`, model `md07x02_cog2026_2578600_int8mv`).
Pluto ships as binaries only — the "Source code" archives on its releases
page contain nothing but the README — so everything here comes from the
binaries: Ghidra 12.1.4 decompilation, disassembly, strings, and the weight
file's header.

Neither the binaries, the weights, nor the decompiled output are in this
repo. `scripts/reproduce.sh` downloads the release (sha256-checked), fetches
the BWAPI 4.4.0 headers, runs Ghidra headless and rebuilds the annotated
decompilation.

## Short answers

**Does it play by looking at the screen?** No. `pluto.dll` reads StarCraft
1.16.1's memory directly (`UnitNodeTable 0x59CCA8`, `BWGame 0x57F0F0`, the
visible/hidden unit lists, `ActiveTileArray`) and uses BWAPI only for the
enemy's race, chat, `leaveGame` and debug drawing. It imports no screen
capture (no gdi32/user32/d3d).

**Does it cheat on fog of war?** No. Reads of other players are filtered the
way BWAPI filters them for an ordinary bot: sprite visibility bits, detection
for cloaked/burrowed units, visible-only creep and occupancy. Enemy
resources, production queues and research in progress are never read.
Borderline items are listed in [docs/observation.md](docs/observation.md).

**How does it issue commands?** It builds raw BW network packets itself (an
inlined copy of BWAPI's `QueueGameCommand` into `TurnBuffer 0x654880`,
`sendTurn 0x485A40`). It does not use BWAPI's `Unit::issueCommand`. It sends
one model action every 6 frames, but that one action can expand into a
select-and-order pair for every unit it affects. It has no 12-unit selection
cap and no camera. See [docs/actions.md](docs/actions.md).

**What is the model?** 315,040,001 parameters, int8 with per-channel scales.
Components:

- unit transformer: 6 layers, 768-wide, 12 heads
- spatial CNN over 128×128 build-tile planes
- 4096-wide GRU core that attends over units, map cells and a slow memory
  (a 4-layer transformer every 8 steps, 128 slots)
- autoregressive heads: action type (20) → argument (233) → either
  coarse 8×8 + fine 16×16 map target, or a unit pointer
- 4-class win head

It samples at temperature 1 with mt19937_64. See [docs/model.md](docs/model.md).

**Are build orders scripted?** No. A Thompson-sampling bandit picks an
opening per opponent and feeds it to the network as a 32-bit mask input. The
network plays the build itself. See
[docs/lifecycle_ipc_bandit.md](docs/lifecycle_ipc_bandit.md).

## Docs

| file | contents |
|---|---|
| [docs/observation.md](docs/observation.md) | memory reads, 6 categorical + 109 continuous unit features, spatial planes, 292 globals, fog-of-war audit |
| [docs/actions.md](docs/actions.md) | 40-byte response, 20 action types, 233-entry arg vocabulary, position encoding, packet opcodes, DLL-side masks, latency probe |
| [docs/lifecycle_ipc_bandit.md](docs/lifecycle_ipc_bandit.md) | engine launch & `PLO1` handshake, `PLSM` shared-memory layout, block/straddle/lockstep timing, build-order bandit, resign, fatal paths |
| [docs/model.md](docs/model.md) | architecture reconstruction with PyTorch-style pseudo-code, int8 scheme, VNNI/AVX2 kernels, threading, `--bench` |
| [docs/weights_tensors.md](docs/weights_tensors.md) | all 269 tensors: name, shape, dtype, offset |

Claims are tagged **[V]** (verified from code, bytes or shapes), **[I]**
(inferred) or **[?]** (open). Each doc ends with its open questions.

## Tools

| path | what |
|---|---|
| `scripts/reproduce.sh` | fetch release + BWAPI headers, decompile, annotate |
| `ghidra_scripts/DecompileAll.java` | headless: every function to one C file |
| `analysis/vtables.py` | BWAPI 4.4.0 interface vtables in MSVC layout (overloads grouped in reverse) → `bwapi_vtables.json` |
| `analysis/bwmem.py` | StarCraft 1.16.1 address → symbol (`Offsets.h`, `BWGame` fields, `unitCounts[type][player]`) |
| `analysis/annotate.py` | appends those names as comments to the decompiled DLL |
| `analysis/weights.py` | `pluto_weights.bin` parser/dequantiser; `--check` validates the container |
| `analysis/dump_bo.py` | build-order arm tables per race |
| `analysis/peread.py`, `rd.py`, `dllread.py` | read bytes, strings and tables at virtual addresses |
| `analysis/fn.sh` | print one decompiled function |

## Running Pluto

It needs Brood War **1.16.1** + BWAPI 4.4.0 (Windows or Wine) and an AVX2
CPU. It cannot play on today's Battle.net, which is StarCraft: Remastered;
BWAPI does not support Remastered, and running bots on the ladder breaks
Blizzard's terms. Play it locally against the built-in AI or other bots,
over LAN, or through a bot tournament manager.

Pluto and its binaries are © their author. This repo contains only notes and
tooling written independently of it.
