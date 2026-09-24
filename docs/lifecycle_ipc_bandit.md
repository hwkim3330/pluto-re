# Pluto: process lifecycle, IPC transport, frame pacing, build-order bandit, resign and error handling

Scope: `release/pluto.dll` (32-bit BWAPI module, build string `"Sep 22 2026"`) and
`release/pluto/pluto_infer.exe` (64-bit CPU engine, build `"Aug 17 2026"`).
Addresses are VAs in the respective image (DLL base 0x63f80000, EXE base 0x140000000).

Legend: **[V]** verified from the decompile *and* checked against disassembly or raw data bytes;
**[I]** inference (naming or semantics not proven by code).

Helper scripts added:
- `analysis/peread.py`: read strings, dwords, floats or doubles at a VA in either binary
  (`python3 peread.py dll 63fd2080 136 x`).
- `analysis/dump_bo.py`: dumps the three build-order arm tables.
- `analysis/infer_ipc_notes.txt`: raw notes on the engine (EXE) side.

Pitfall seen while doing this: Ghidra types the frame counter as `uint *`. So `frame + 0x3c` in the
decompile is really `frame + 0xf0` frames, and `+ 0x18` is `+ 0x60`. Every frame constant below was
re-read from the disassembly.

---

## 0. Key DLL globals

| Address | Meaning |
|---|---|
| `DAT_63ff1034` | `BWAPI::Game*` |
| `DAT_63fd2300` | self player id (onStart arg 1) |
| `DAT_63fd213c` | enemy race (onStart arg 2; 0=Z, 1=T, 2=P, >2 means unknown/random) |
| `DAT_63fd2140` | `EngineClient` object (layout in §1.4) |
| `DAT_63ff165c` | pacing mode: 0=block, 1=straddle, 2=lockstep |
| `DAT_63fd2128` | frame budget, double ms; default 40.0, floor 5.0 |
| `DAT_63ff165a` / `DAT_63ff1659` | `BWRL_DRAW` / `BWRL_STDOUT` flags |
| `DAT_63ff1661` | engine up |
| `DAT_63ff1658` | request in flight (pending) |
| `DAT_63ff1654` | next observation frame |
| `DAT_63fd2120` | frame of the in-flight observation |
| `DAT_63ff1560..` | retained copy of the in-flight observation (unit list etc.); `DAT_63ff1650` = retained-valid |
| `DAT_63ff1180` | fatal message buffer (0x180 bytes); non-empty means the fatal state |
| `DAT_63fd2108` | frame at which to leave the game or kill the process (-1 = none) |
| `DAT_63ff1680` | `BanditStore` object (§4.4) |
| `DAT_63ff16fc` | matchup key = own_race*4 + (opp_race+1) |
| `DAT_63ff1700` | chosen mask |
| `DAT_63ff1718` | pick awaiting credit |
| `DAT_63ff2318[32]` | float mask bits (model input) |
| `DAT_63ff2398[3]` | opponent-race one-hot (model input) |

---

## 1. Process lifecycle

### 1.1 onStart: `FUN_63f85f90(self_id, enemy_race)` [V]

1. Resets all per-game state and logs `"BWRL: onStart (player %d, opp race %d)"`.
2. Reads the environment:
   - `BWRL_LOCKSTEP`: non-empty and not starting with `'0'` gives mode 2. It takes precedence.
   - else `BWRL_STRADDLE`: non-empty and not `'0'` gives mode 1.
   - else mode 0 (block).
   - `BWRL_FRAME_BUDGET_MS`: `atof`, clamped to at least 5.0 (`DAT_63fda9b0`=5.0f). The default of
     40.0 comes from initialised data at `DAT_63fd2128`.
   - `BWRL_DRAW` and `BWRL_STDOUT`: non-empty and not `'0'`.
3. Calls `timeBeginPeriod(1)` and logs `"BWRL: %s client (frame budget %.0f ms, draw %s, stdout %s)"`.
4. Sets the opponent-race one-hot `DAT_63ff2398[enemy_race] = 1.0f` (only if enemy_race < 3).
5. Finds the opponent name. It takes the first player slot other than self whose `Players[i].type`
   (0x57EEE8 + 0x24*i) is 1 or 2 (Computer or Human), then copies 25 bytes of `Players[i].name`
   (0x57EEEB + 0x24*i) to `DAT_63ff1130`.
   - The name is sanitised: characters outside `[A-Za-z0-9_\-./]` become `'_'`; the result is at most
     25 characters; an empty name becomes `"unknown"`.
   - The sanitised name is the key of the bandit file.
6. Own race is `Players[self].race` (0x57EEE9), set to -1 if >2. Opponent race is set to -1 if >2.
7. Build-order bandit pick (§4). It runs only when own race is known. It loads the bandit store
   (`FUN_63fbc670`) first.
8. Writes the mask into the model-input vector: `DAT_63ff2318[i] = 1.0f` for each set bit i (32 floats).
9. Logs `"BWRL: own_race=%d opp_idx=%d opp="%s" -> BO %s (mask=0x%x, %d arms)"`.
10. Kills any previous engine (`FUN_63fb7190(&DAT_63fd2140)` if `DAT_63ff1661`).
11. Resolves the engine path:
    - `GetModuleFileNameW(hDll)`, where the DLL handle `DAT_63ff1030` was saved in DllMain. The buffer
      grows from 0x104 up to 0x8000 wide characters.
    - Strips the file name after the last `\` or `/`, then appends `L"pluto\\pluto_infer.exe"`.
    - Converts to UTF-8.
    - Failure gives `"exe path resolution failed"`.
12. Launch loop (disassembly at 0x63f880c8..0x63f88196) [V]:
    ```
    for attempt = 1 .. 9:
        logpath = "" + "pluto_infer.log"      // FUN_63f81530() returns "" -> the CWD (StarCraft folder)
        ok = EngineClient::start(&DAT_63fd2140, exe_utf8, logpath, 180000 /*ms handshake timeout*/)
        if ok: break
        if attempt == 9 or !client.retryable(+0x31): fail
        log "BWRL: engine launch attempt %d/%d failed (%s) - retrying in %lu ms"   (d/9, 750)
        Sleep(750)
    ```
13. On success:
    - Copies `frames_per_step` into `DAT_63fd2138` and `max_units` into `DAT_63ff23a4`.
    - Logs `"BWRL: inference server up (%s; %s [%s], frames_per_step=%d, max_units=%d, %s transport)"`
      with the exe path, model string, engine string, fps, max_units, and `"shm"` or `"pipe"`.
    - Sets `DAT_63ff1661 = 1`, and sets `DAT_63ff1174 = 1` so that `"Pluto online (%s). gl hf!"` is
      sent on the first frame.
14. On failure:
    - Logs `"BWRL: failed to launch inference server (%s): %s"`.
    - Builds the fatal text `"Pluto: %s: %s"` from `"engine failed to start"` and the client error. When
      available, the error is extended with `"%s; engine log: %s"`, where the second part is the
      **last non-empty line of `pluto_infer.log`** (`FUN_63f81770`).
    - Writes an `event` record with `what: "fatal"` (§5.3).
15. Writes the `start` record (§5.2) and saves the bandit file (`FUN_63fbcab0`). If the seq returned by
    the write differs from the expected one, it logs
    `"BWRL: start record write got seq %lld (expected %lld)"` and uses id -1.

### 1.2 `EngineClient::start` = `FUN_63fb5420(this, exe, logpath, timeout_ms)` [V]

- `this+0x31` (retryable) is set to 1 on entry.
- Pipes and handles:
  - Two anonymous pipes are created with `SECURITY_ATTRIBUTES{bInheritHandle=TRUE}`:
    - request pipe: the child's stdin is the read end; the DLL keeps the write end at `this+4`;
    - response pipe: the child's stdout is the write end; the DLL keeps the read end at `this+8`.
  - The parent-side ends are made non-inheritable with `SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0)`.
  - Errors: `"CreatePipe(req) failed (error %lu)"` and `"CreatePipe(resp) failed (error %lu)"`.
- Shared memory, unless `BWRL_SHM` starts with `'0'`:
  - `CreateFileMappingA(INVALID_HANDLE_VALUE, &inheritSA, PAGE_READWRITE, 0, 0x85F80, NULL)`, which is
    anonymous and inheritable.
  - `MapViewOfFile(.., FILE_MAP_ALL_ACCESS)`.
  - Zeroes the header bytes 0x10..0xC0 and writes the header fields (§2).
  - Two auto-reset, unnamed, inheritable events: `CreateEventA(&sa, FALSE, FALSE, NULL)` for the
    request event (`this+0x10`) and the response event (`this+0x14`).
  - `DuplicateHandle(GetCurrentProcess() -> inheritable, SYNCHRONIZE (0x100000))` gives the "parent"
    handle the child waits on.
  - The handle values are passed as environment variables formatted `"%llu"` via
    `SetEnvironmentVariableA` (the child inherits the environment):
    - `PLUTO_SHM_SEC`: the mapping handle;
    - `PLUTO_SHM_REQ_EV`: the request event;
    - `PLUTO_SHM_RESP_EV`: the response event;
    - `PLUTO_SHM_PARENT`: the duplicated handle of the StarCraft process.
  - After `CreateProcess` all four variables are cleared (set to NULL) and the parent handle is closed.
  - If any shared-memory object fails, it is torn down silently and the pipe transport is used.
- Engine stderr: `CreateFileA(logpath, GENERIC_WRITE, FILE_SHARE_READ, &inheritSA, CREATE_ALWAYS,
  FILE_ATTRIBUTE_NORMAL)`, so `pluto_infer.log` is truncated on every launch.
- Command line: exactly `"<exe path>"` (the quoted path, **no arguments**). The application name is the
  wide exe path.
- `CreateProcessW(app, cmdline, NULL, NULL, bInheritHandles=TRUE, CREATE_NO_WINDOW (0x08000000), NULL env
  (inherits), NULL cwd (inherits StarCraft's CWD), &si{cb=0x44, dwFlags=STARTF_USESTDHANDLES, hStdInput=req_rd,
  hStdOutput=resp_wr, hStdError=logfile}, &pi)`.
- Long-path retry: if `CreateProcessW` fails, the path length is ≥ 0xF8 (248) characters, and the path
  is drive-letter absolute (`X:`), it retries with a `\\?\` prefix (branch at `LAB_63fb683d`).
- On failure:
  - message `"CreateProcess failed (error %lu%s)"`, where the suffix is `" = exe not found"` for error
    2 or 3 and `" = bad exe format; 32-bit-only Wine prefix?"` for error 193;
  - `retryable = !(err==2 || err==3 || err==193)`;
  - everything is closed.
- On success: stores `hProcess` at `this+0`, closes `hThread`, and waits for the handshake:
  - Every 100 ms (`WaitForSingleObject(hProcess,100)`) it calls `PeekNamedPipe` on the response pipe
    until at least 0x88 bytes are available, then `ReadFile`s exactly 0x88 bytes.
  - Timeout (`GetTickCount` delta > `timeout_ms` = 180000):
    `"no handshake within %lu ms (server hung loading? see pluto_infer.log)"`.
  - If the process exits first, it peeks once more. When the data is not there, `FUN_63fb51a0` formats
    `"%s; server exited (code %lu / 0x%lx) — see pluto_infer.log"` (or `"%s; server still running"`).
    The base texts are `"server exited before handshake"`, `"stdout pipe broke before handshake"` and
    `"handshake read failed (error %lu)"`.
- Handshake validation (`LAB_63fb6480`):
  - requires magic == `'PLO1'` (0x314F4C50), version == 3, frames_per_step > 0 and max_units > 0;
  - otherwise `"bad handshake (magic 0x%08lx version %ld)"` with `retryable = 0`;
  - `max_units > 0x400` gives `"handshake max_units %d exceeds protocol cap %d"` with `retryable = 0`.
  - If the model name is empty it becomes `"model v%lld"`, using the model version.
- Transport activation: `this+0x1c` (use_shm) = `shm != NULL && *(u32*)(shm+0x10) == 'PLSM'`. The engine
  writes that acknowledgement before it sends the handshake, so the check cannot race.
- The error text lives at `this+0xBC` (0x100 bytes, written by `FUN_63fb70e0`, which is a vsnprintf).

### 1.3 Handshake record (engine to DLL, 0x88 bytes on stdout, always sent even with shm) [V both sides]

```c
struct PlutoHandshake {            // default template in the DLL at 0x63fd2080 = {'PLO1', 3, 0...}
  uint32_t magic;                  // +0x00 'PLO1' = 0x314F4C50
  int32_t  version;                // +0x04 3
  int32_t  frames_per_step;        // +0x08 6 for this model        -> client+0x34
  int32_t  max_units;              // +0x0C 768 for this model      -> client+0x38 (must be <= 1024)
  int64_t  model_version;          // +0x10 2578600 ("ckpt")        -> client+0x40
  char     model[0x30];            // +0x18 "md07x02_cog2026_2578600_int8mv" -> client+0x48
  char     engine[0x40];           // +0x48 "%s%s %dt%s %s" = backend,"(fp32)"?,threads," vnni"?,build date
};                                 //        e.g. "int8mv 6t vnni Aug 17 2026"  -> client+0x78
```

### 1.4 `EngineClient` (at `DAT_63fd2140`) [V offsets; I names]

| Offset | Field |
|---|---|
| 0x00 | `hProcess` |
| 0x04 | request-pipe write end |
| 0x08 | response-pipe read end |
| 0x0C | `hMapping` |
| 0x10 | `hReqEvent` |
| 0x14 | `hRespEvent` |
| 0x18 | `shm` view pointer |
| 0x1C | `use_shm` (u8) |
| 0x20 | `req_seq` (u32) |
| 0x28 | QPC frequency (i64) |
| 0x30 | `ok` (u8) |
| 0x31 | `retryable` (u8) |
| 0x34 | `fps` |
| 0x38 | `max_units` |
| 0x40 | `model_version` (i64) |
| 0x48 | `model[0x30]` |
| 0x78 | `engine[0x40]` |
| 0xBC | `err[0x100]` |

### 1.5 Engine side (`pluto_infer.exe`, main `FUN_1401501f0`) [V; detail in `analysis/infer_ipc_notes.txt`]

- Startup checks and settings:
  - CPU: needs AVX2 and FMA, else it prints "this CPU lacks AVX2/FMA" and exits 1.
  - Affinity: widened to all CPUs unless `BWRL_KEEP_AFFINITY` is set (`FUN_140083c10`).
  - Flags: `--blob --backend pk|int8|int8mv --threads --bench --seed --argmax --log --verbose --ptx(ignored)
    --prof*`. An unknown argument gives exit 2. The DLL passes no arguments.
  - Weights: `pluto_weights.bin` (container `'PLWB'` v1, u64 JSON length, then a JSON header).
    `pluto_config.json` sits next to it and supplies `backend` and `threads`.
  - Thread default: min(6, number of CPUs in the affinity mask). `BWRL_ENGINE_THREADS`, `BWRL_INT8`,
    `BWRL_INT8_MATVEC` and `BWRL_NO_VNNI` override it.
  - A model max_units > 0x400 gives "exceeds protocol cap %d (kShmMaxUnits); refusing to serve" and
    exit 1 (0x1401527c2). **kShmMaxUnits = 1024.**
- Shared-memory attach (0x140151c02):
  - Parses the four environment variables with `_strtoui64`; if any is missing or zero it silently
    uses pipes.
  - Maps the view and checks `'PLSM'`, 3, 0x85F80 and 0x400. On mismatch it logs "shm header mismatch
    ...; using pipes".
  - Writes the acknowledgement `'PLSM'` at +0x10, then sends the handshake.
- Serving loop (0x140151f3e):
  ```
  for (;;) {
    if (shm->quit) exit(0)                              // "quit flag set"
    if (shm->req_seq != last) { serve(); continue; }
    r = WaitForMultipleObjects(2, {reqEv, parent}, FALSE, INFINITE)
    if r == 0: continue; if r == 1: "parent process exited"; else "shm wait failed"; -> exit(0)
  }
  serve: last = req_seq; copy header+arrays out; step (FUN_140034f10);
         write response @0x85F40; resp_seq(@0x80) = last; SetEvent(respEv); FUN_14002b8d0 (prelude for next step [I])
  ```
- Request header check: `N<1 || N>max_units || W!=128 || H!=128` gives "bad request header" and exit 1.
- Exit codes: 0 = clean (quit flag, parent gone, EOF on stdin); 1 = fatal; 2 = usage. All logging goes
  to stderr (unbuffered), which is `pluto_infer.log`.

### 1.6 Shutdown [V]

`FUN_63fb7190` handles an orderly stop: at onEnd, before a relaunch, and on handshake failure.

1. If shm exists and a process exists, set `shm->quit (+0x14) = 1` and `SetEvent(reqEv)`.
2. Close both pipe ends. In pipe mode the engine sees EOF and exits 0.
3. `WaitForSingleObject(hProcess, 3000)`. On timeout, `TerminateProcess(hProcess, 1)`.
4. Unmap the view and close the mapping and events. Reset `use_shm`, `req_seq` and `ok`.

`FUN_63fb5230` is the I/O-error variant. It records `"pipe I/O failed (error %lu)"` plus exit status, then
runs the same teardown.

The engine also exits by itself when StarCraft dies, via the `PLUTO_SHM_PARENT` wait.

---

## 2. Shared-memory transport

### 2.1 Layout (one anonymous mapping, 0x85F80 = 548,736 bytes) [V, both sides agree]

```c
#define kShmMaxUnits 1024
struct PlutoShm {                       // DLL writes 0x00-0x0C at create; zeroes 0x10-0xBF
  uint32_t magic;          // 0x000 'PLSM' 0x4D534C50                          (DLL)
  uint32_t version;        // 0x004 3                                           (DLL)
  uint32_t size;           // 0x008 0x85F80                                     (DLL)
  uint32_t max_units_cap;  // 0x00C 0x400                                       (DLL)
  uint32_t ack;            // 0x010 'PLSM' written by engine on attach          (engine)
  uint32_t quit;           // 0x014 1 = engine must exit                        (DLL at shutdown)
  uint8_t  _pad0[0x28];
  uint32_t req_seq;        // 0x040 incremented by DLL per request (client+0x20) (DLL)
  uint8_t  _pad1[0x3C];
  uint32_t resp_seq;       // 0x080 = req_seq the engine just answered          (engine)
  uint8_t  _pad2[0x3C];
  struct ReqHeader {       // 0x0C0 (0x30 bytes; identical to the pipe header)
    int32_t  num_units;    //  +0x00 N, 1..max_units (DLL rejects N-1 >= 0x400: "num_units %d out of shm range")
    int32_t  map_w;        //  +0x04 128  (engine requires 128)
    int32_t  map_h;        //  +0x08 128  (engine requires 128)
    uint32_t flags;        //  +0x0C bit0 = forced action present (DLL always writes 0)
    int64_t  forced[4];    //  +0x10 {a, arg, pos, u} forced action (DLL always writes 0)
  } hdr;
  uint8_t  _pad3[0x10];
  int64_t  unit_ints[kShmMaxUnits][6];      // 0x00100  0x30 B/unit (ids, type, order, owner ... [I])
  float    unit_cont[kShmMaxUnits][109];    // 0x0C100  0x1B4 B/unit, clamped to [-5,5] by DLL
  uint8_t  unit_u8a[kShmMaxUnits];          // 0x79100
  uint8_t  unit_u8b[kShmMaxUnits];          // 0x79500
  uint8_t  flags20[20];                     // 0x79900 (region 0x40)
  uint8_t  flags233[233];                   // 0x79940 (region 0x100)
  float    global[292];                     // 0x79A40 (0x490 B; region 0x4C0) - see 4.6
  uint16_t map16[128*128];                  // 0x79F00 spatial map
  uint8_t  map8[128*128];                   // 0x81F00 spatial map
  int64_t  hist[4];                         // 0x85F00 last 4 action types [I] (from DAT_63ff2234, stride 0x2C)
  uint8_t  _pad4[0x20];
  struct Resp {                             // 0x85F40 (0x28 bytes; identical to pipe response)
    int64_t a;             // action type
    int64_t arg;           // action argument (unit type / order ...) [I]
    int64_t pos;           // coarse*256 + fine: 8x8 coarse blocks of 16x16 build tiles (see actions.md, "Position")
    int64_t u;             // selected unit index in the observation, -1 = none
    float   win;           // value head: win estimate in [-1,1]; -1000 = n/a (pipe default)
    float   lp;            // log-prob of the chosen action
  } resp;
  uint8_t  _pad5[0x18];                     // 0x85F68..0x85F80
};
```

Evidence:
- DLL writer: `FUN_63fb4bc0`, which does all the memcpy's to the offsets above, then `req_seq++`,
  then `SetEvent(reqEv)`.
- DLL reader: `FUN_63f83050`.
- The engine side is at 0x140151f3e.
- Region sizes follow from the next offset: unit regions are exactly 1024 × stride, which confirms
  kShmMaxUnits = 1024.

Only N rows of each per-unit array are copied (`vector.size()` bytes). The DLL keeps unit row 0
reserved: it truncates the real units to `max_units-1` and sets N = units + 1
(`"WARNING: %d units truncated to %d (max_units=%d)"` in `FUN_63fafd80`). The reserved row itself is [V];
what row 0 means is [I].

### 2.2 Synchronisation protocol [V]

The protocol is a single-slot request/response with monotonically increasing sequence numbers.

- **DLL send** (`FUN_63fb4bc0`): write header and arrays, `client.req_seq += 1`, `shm->req_seq = req_seq`,
  `SetEvent(reqEv)`.
- **Engine**: wakes on reqEv, sees `req_seq != last`, serves, writes `resp`, sets `resp_seq = req_seq`,
  `SetEvent(respEv)`.
- **DLL receive** (`FUN_63f83050(out..., deadline_qpc, lockstep)`):
  ```
  loop:
    if shm->resp_seq == client.req_seq: copy resp (0x28 bytes); return 1
    if !lockstep: if QPC >= deadline: return 0            // not ready yet
    r = WaitForMultipleObjects(2, {respEv, hProcess}, FALSE,
                               lockstep ? INFINITE : ceil_ms(deadline-now))
    r in {0, WAIT_TIMEOUT}: loop
    r == 1 (engine died): format "server exited (code ..)" / "server still running"; teardown; return -1
    else: "shm wait failed (error %lu)"; teardown; return -1
  ```
- In the `lockstep` path the wait is `INFINITE` and no deadline is checked.
- `-1` leads to `FUN_63f85a70`, the fatal "engine connection lost" handler (§6).

### 2.3 Pipe transport (`BWRL_SHM=0`, or a failed shm create or attach) [V]

- Request: the same 0x30-byte header, then the arrays **contiguously, with no padding**, in shm order.
  The sizes are N·0x30, N·0x1B4, N, N, 20, 233, 292·4, 0x8000, 0x4000, 0x20. After the header, the DLL
  writes them with `WriteFile` loops.
- Response: 0x28 bytes. The DLL polls `PeekNamedPipe` until at least 0x28 bytes are available, spinning
  with a short busy loop between polls, and returns 0 at the deadline. It then reads.
- The pipe-mode defaults written before the read are `u=-1` and `win=-1000.0f` (0xC47A0000).
- Any `ReadFile`, `WriteFile` or `PeekNamedPipe` failure goes to `FUN_63fb5230`, which reports
  "pipe I/O failed" and triggers the fatal path.

---

## 3. Frame pacing: `onFrame` = `FUN_63f8baf0` [V unless marked]

Per call:

- **Frame start.** `t0 = QPC()` at entry. `deadline = t0 + round(freq * 0.001 * budget_ms)`, where
  0.001 is `DAT_63fdaa20` and budget_ms is 40 by default.
- **Map-size check.** If the map is wider or taller than 128 tiles: `"Map exceeds %d tiles (%dx%d)"`,
  then `FUN_63fcf787` (abort).
- **Once per game frame.** If `frame == DAT_63fd2130` (the same frame seen again, e.g. while paused),
  it only does cleanup.
- **Command injection.** Queued raw commands (`DAT_63ff230c`) are replayed into BW's `TurnBuffer`
  (0x654880), with a turns-in-transit check through storm ordinals 0x72 and 0x73 [I: queue-space check].
- **Latency probe.** Runs until frame 240 (§6.3).
- **Fatal or resign state machine** (§5, §6).
- **Normal path**, when `DAT_63fd2108 < 0`:
  - First frame with the engine up: sends `"Pluto online (%s). gl hf!"`.
  - **Not pending, `frame >= next_obs`, and engine up:**
    1. Build the observation (`FUN_63fafd80`) and send it (`FUN_63fb4bc0`). A send failure is fatal.
    2. `pending = 1`, `obs_frame = frame`. The observation is retained so the response is decoded
       against the unit list it was computed from.
    3. `r = recv(deadline, lockstep = (mode == 2))`. So block and straddle wait **until frame start
       + budget** in the observing frame; lockstep waits indefinitely. In lockstep the wait time is
       added to the "blocked" accumulator.
    4. `r == 1`: apply now (`FUN_63f8a9f0`).
  - **Pending** (answer not received in the observing frame):
    - block mode: `deadline = now + freq` (**1 s**). If there is still no answer, it logs
      `"BWRL: block: obs F%d still unanswered after %.0f ms — re-polling (slip)"`, returns, and
      re-polls next frame. The time waited is added to the "blocked" accumulator (`DAT_63ff1340`).
    - straddle mode: `deadline = frame start + budget`, so the game is never held longer than the
      budget. A late answer slips to a later frame.
    - With an answer: if no retained observation exists, it logs
      `"response with no retained observation — dropping"`; otherwise it applies.
- **Apply** (`FUN_63f8a9f0(frame, resp...)`):
  - `pending = 0`.
  - Stale check: units of the retained observation that are gone by now (dead or re-fogged) are
    counted into `reval_steps`, `stale_units` and `stale_max`.
  - Decodes the action (`FUN_63faf4b0(&DAT_63ff2100, retained, a, arg, pos, u)`).
  - `eff = (frame == obs_frame) ? obs_frame + 1 : frame`.
  - `next_obs = max(eff + fps - 1, obs_frame + fps)`. With fps = 6, an answer in-frame or on the next
    frame keeps the 6-frame cadence.
  - `slip = eff - (obs_frame + 1)`, counted in buckets 0/1/2/3+ (`DAT_63ff1528[4]`), with the maximum
    in `DAT_63ff1524`. A slip above 0 logs
    `"BWRL: %s: obs F%d flushed F%d (slip %d, infer %.1f ms), next obs F%d"`.
  - Inference time is measured from send to apply (the DLL wall clock, IPC included) and gives
    `infer_avg_ms` and `infer_max_ms`.
- **Frame-wall accounting.** `wall = QPC() - t0`, tracked as `max_frame_ms`.
  - `wall > 46.9 ms` (`DAT_63fda958`) increments `over47`.
  - `wall > 55.0 ms` (`DAT_63fda960`) increments `over55`, and the first 20 occurrences log
    `"BWRL: frame wall %.1f ms > 55 (over-budget #%d)"`.

Mode summary:

| mode | env | observing frame | following frames | effect |
|---|---|---|---|---|
| block (0, default) | none | wait ≤ budget | wait up to 1 s per frame until the answer arrives | the decision lands on obs+1 (slip 0) and the game stalls instead; it only slips if an answer is more than 1 s late on a frame |
| straddle (1) | `BWRL_STRADDLE=1` | wait ≤ budget | wait ≤ budget per frame | no frame held past the budget; decisions slip |
| lockstep (2) | `BWRL_LOCKSTEP=1` | wait forever | none | deterministic, no slip; stall accounted as blocking |

**"Can't keep up" detector** (in `FUN_63f8a9f0`, once per game via `DAT_63ff1348`):
- It keeps a ring of the last 20 steps, holding slip, blocking ms and infer ms.
- When the ring is full:
  - block mode: if Σblocking ≥ 840 ms and more than 10 of 20 steps blocked, it sends
    `"Pluto: this machine can't keep up (inference ~%.0f ms/step, stalling the game ~%.0f ms per decision) - sorry about the pace"`.
  - other modes: if Σslip > 39 frames and more than 10 of 20 steps slipped, it sends
    `"... decisions ~%.1f frames late) - gameplay may be degraded"`.
  - The message is logged, echoed to stdout if `BWRL_STDOUT` is set, and sent to chat in chunks of
    64 characters or fewer (`FUN_63f81850`). It also writes an `event` record with `what: "degraded"`.
- With `BWRL_STDOUT` set, every step also prints `"F%d win=%.3f"`, or `"F%d win=n/a"` when win ≤ -100.

---

## 4. Build-order bandit

### 4.1 Arm tables [V, raw data dumped by `analysis/dump_bo.py`]

Each entry is 20 bytes: `{u32 mask; f32 prior_vsZ; f32 prior_vsT; f32 prior_vsP; char* name}`.
- Zerg: 21 arms @0x63fdd8a0.
- Terran: 23 arms @0x63fdda60.
- Protoss: 22 arms @0x63fddc40.

The priors look like offline win rates of each arm per opponent race [I].

Zerg:

| mask | vsZ | vsT | vsP | name |
|---|---|---|---|---|
| 0x00000000 | .473 | .199 | .602 | free |
| 0x00000001 | .471 | .198 | .600 | free+hint |
| 0x00020000 | .394 | .177 | .592 | 9PoolSpeed |
| 0x00040000 | .539 | .247 | .670 | 12HatchFE |
| 0x00080000 | .537 | .233 | .670 | 3HatchMuta |
| 0x00100000 | .520 | .220 | .672 | Lurker |
| 0x00200000 | .509 | .168 | .673 | HydraMass |
| 0x00400000 | .538 | .199 | .639 | Defiler |
| 0x00800000 | .525 | .189 | .643 | UltraLing |
| 0x01000000 | .481 | .164 | .639 | 2HatchHydra |
| 0x08020000 | .402 | .185 | .566 | o:9Pool |
| 0x08040000 | .512 | .223 | .621 | o:Sunken |
| 0x08080000 | .478 | .216 | .617 | o:12Pool |
| 0x09000000 | .434 | .189 | .595 | o:4Pool |
| 0x10080000 | .540 | .245 | .650 | 3HatchMuta~tr |
| 0x10100000 | .525 | .241 | .662 | Lurker~tr |
| 0x10200000 | .524 | .195 | .673 | HydraMass~tr |
| 0x10400000 | .546 | .218 | .653 | Defiler~tr |
| 0x10800000 | .539 | .222 | .652 | UltraLing~tr |
| 0x11000000 | .502 | .197 | .651 | 2HatchHydra~tr |
| 0x20100000 | .510 | .186 | .586 | LurkDefiler |

Terran:

| mask | vsZ | vsT | vsP | name |
|---|---|---|---|---|
| 0x00000000 | .832 | .558 | .592 | free |
| 0x00000001 | .831 | .555 | .590 | free+hint |
| 0x00000002 | .790 | .380 | .598 | BBS |
| 0x00000004 | .769 | .519 | .579 | 1FactCC |
| 0x00000008 | .738 | .516 | .680 | 2FactVult |
| 0x00000010 | .762 | .514 | .528 | SiegeExpand |
| 0x00000020 | .744 | .491 | .551 | 2PortWraith |
| 0x00000040 | .772 | .530 | .533 | 1RaxFE |
| 0x00000080 | .715 | .530 | .340 | Goliath |
| 0x00000100 | .820 | .460 | .552 | CCFirst |
| 0x02000000 | .794 | .360 | .592 | 2RaxBioFE |
| 0x08000004 | .819 | .559 | .608 | o:RaxFact |
| 0x08000040 | .827 | .555 | .585 | o:1RaxFE |
| 0x08000100 | .843 | .539 | .587 | o:14CC |
| 0x10000004 | .804 | .529 | .622 | 1FactCC~tr |
| 0x10000008 | .790 | .541 | .699 | 2FactVult~tr |
| 0x10000010 | .808 | .534 | .610 | SiegeExpand~tr |
| 0x10000020 | .794 | .535 | .612 | 2PortWraith~tr |
| 0x10000040 | .816 | .541 | .607 | 1RaxFE~tr |
| 0x10000080 | .780 | .536 | .526 | Goliath~tr |
| 0x10000100 | .835 | .490 | .580 | CCFirst~tr |
| 0x12000000 | .795 | .410 | .610 | 2RaxBioFE~tr |
| 0x22000000 | .798 | .321 | .533 | Vessel |

Protoss:

| mask | vsZ | vsT | vsP | name |
|---|---|---|---|---|
| 0x00000000 | .417 | .452 | .521 | free |
| 0x00000001 | .416 | .450 | .520 | free+hint |
| 0x00000200 | .371 | .410 | .485 | 4Gate |
| 0x00000400 | .340 | .448 | .508 | 12Nexus |
| 0x00000800 | .362 | .405 | .511 | 1GateRobo |
| 0x00001000 | .382 | .392 | .521 | Speedlot |
| 0x00002000 | .404 | .401 | .483 | Corsair |
| 0x00004000 | .347 | .449 | .474 | Storm |
| 0x00008000 | .391 | .415 | .533 | DTRush |
| 0x00010000 | .326 | .418 | .458 | Carrier |
| 0x04000000 | .262 | .309 | .421 | FFE |
| 0x08000400 | .368 | .470 | .510 | o:14Nexus |
| 0x08000800 | .426 | .477 | .527 | o:1GateCore |
| 0x08001000 | .412 | .431 | .508 | o:2Gate |
| 0x10000400 | .349 | .464 | .520 | 12Nexus~tr |
| 0x10000800 | .386 | .439 | .553 | 1GateRobo~tr |
| 0x10002000 | .426 | .440 | .539 | Corsair~tr |
| 0x10004000 | .374 | .463 | .525 | Storm~tr |
| 0x10008000 | .394 | .417 | .560 | DTRush~tr |
| 0x10010000 | .373 | .450 | .504 | Carrier~tr |
| 0x14000000 | .251 | .305 | .403 | FFE~tr |
| 0x20004000 | .263 | .359 | .417 | Arbiter |

Mask bit semantics:
- **[V]**, the bit layout itself:
  - bit 0 = "hint";
  - bits 1-8 = Terran builds;
  - bits 9-16 = Protoss builds;
  - bits 17-24 = Zerg builds;
  - bit 25 = 2RaxBioFE;
  - bit 26 = FFE.
- **[I]**, what the flag bits mean:
  - bit 27 (`o:`) = opening-only variant. It reuses a build bit: for example `o:4Pool` = bit 27 | bit 24,
    and bit 24 alone is 2HatchHydra, so a build bit means something else under `o:`.
  - bit 28 (`~tr`) = alternate variant of the same build. The code treats it as the "twin" of the base
    arm (see pooling).
  - bit 29 = late-tech extension (LurkDefiler = Lurker | b29; Vessel = 2RaxBioFE | b29;
    Arbiter = Storm | b29).

### 4.2 How the mask reaches the model [V]

- onStart sets `DAT_63ff2318[i] = 1.0f` for every set bit of the chosen mask (32 floats).
- Every frame, onFrame copies these 32 floats into the observation (`local_c8`, which is dword 0x11 of
  the observation struct) together with the opponent-race one-hot (dword 0x31).
- In the observation builder (`FUN_63fafd80`), `global[4..35] = mask bits` and
  `global[289..291] = opp race one-hot`.
- So the build order is a **conditioning input** in the 292-float global vector
  (shm 0x79A40 + 4·4). No scripted build is executed; the network is conditioned on the 32 bits.
- Other global slots [V]:
  - [0] minerals and [1] gas, each through `FUN_63fabce8` (a log or sqrt compression [I]), divided by
    `DAT_63fda9f0`;
  - [2] supply used/200 and [3] supply max/200, from the race-summed `Game.supplies` tables;
  - [36..55] 20 booleans;
  - [56..288] 233 booleans.
- All globals are clamped to [-5,5] with the warning `"WARNING: global[%d] = %.3f"`.

### 4.3 Selection: Thompson sampling (onStart, `FUN_63f85f90` ~0x63f87260..0x63f87d40) [V]

Only the arms of the own-race table are considered. For each arm with mask m:

```
(w, l)   = stats[matchup][m]                         // doubles; 0,0 if absent
(wt, lt) = stats[matchup][m ^ 0x10000000]            // the "~tr" twin (base <-> ~tr)
if wt+lt > 0:  k = min(0.5*(wt+lt), 8.0)             // DAT_63fda9a0=0.5, DAT_63fda9b4=8.0
               w += wt*k/(wt+lt);  l += lt*k/(wt+lt) // twin evidence at half weight, capped at 8 pseudo-games
p        = prior[opp_race]  or mean(prior[0..2]) if the opponent race is unknown or random (/3.0)
alpha    = 1 + 6*p + w                               // DAT_63fda9bc = 6.0 prior pseudo-games
beta     = 1 + 6*(1-p) + l
x ~ Gamma(alpha,1), y ~ Gamma(beta,1); theta = x/(x+y)  (0.5 if x+y<=0)
pick argmax theta (strict >, first wins ties)
```

- `FUN_63f85bb0` is libstdc++ `std::gamma_distribution<double>`: Marsaglia-Tsang with d = a - 1/3 and
  c = 1/sqrt(9d); a normal from the polar method; the α<1 boost via U^(1/α).
- The RNG is `std::mt19937_64` at `BanditStore+0xA0` (= `DAT_63ff1720`). It is statically initialised
  with the default seed 5489, then reseeded lazily (`FUN_63fbc4b0`, or inline in `FUN_63f88b60`) from
  `std::random_device("default")` (two 32-bit draws) XOR `GetTickCount64()` XOR
  (this · 0x9E3779B97F4A7C15). The inline copy has the constant folded as 0xDC3266DD / 0xC3D2D880.
- The chosen mask goes to `DAT_63ff1700`, and `DAT_63ff1718 = 1` marks the pick as awaiting credit.
  The chosen arm's raw counts are logged as `arm_w` / `arm_l`.
- If own race is unknown (>2), no pick is made: the mask stays 0 and no credit is given.

### 4.4 File format: `bwapi-data/{read,write}/pluto_bandit_<opp>.txt` [V]

Path builder: `FUN_63fbfbe0(store, "read"|"write")` builds `"bwapi-data/" + sub + "/pluto_bandit_" + opp + ".txt"`.

**Load** (`FUN_63fbc670`) parses both files with `FUN_63fbe600`.
- Parser rules:
  - lines are at most 4095 characters, and a longer line invalidates the file;
  - CR and LF are stripped and empty lines are skipped;
  - `#` lines are comments;
  - `seq <u64>` (strtoull base 10) is accepted only before the first data line;
  - `end` must be present, and any non-comment line after `end` invalidates the file;
  - lines starting with `{` are kept verbatim as JSON records;
  - every other line must scan as `"%7s %7s %x %lf %lf"` = own, opp, mask, wins, losses:
    - own is `Z|T|P` or `0..2`;
    - opp is `Z|T|P|?` or `-1..2`;
    - wins and losses must be finite and ≥ 0;
    - a mismatch invalidates the **whole** file;
    - duplicate (own, opp, mask) lines are **summed**.
  - The key is `own*4 + opp + 1`.
- Choosing a copy: write/ is used unless read/ is valid and (write/ is invalid or
  `read.seq > write.seq`). Ties go to write/.
- The store is re-loaded at onStart, before the start record, before each event record, and at onEnd
  before crediting. So another writer's newer copy is honoured.

**Save** (`FUN_63fbcab0`):
- Runs `CreateDirectoryA("bwapi-data")` and `CreateDirectoryA("bwapi-data/write")`.
- Writes `...txt.tmp`, `seq = seq + 1`, then `MoveFileExA(tmp, final, MOVEFILE_REPLACE_EXISTING)`.
  If the move fails it deletes the tmp file and returns false.
- Contents, in order:
  ```
  # pluto snapshot: build-order bandit stats + one-line JSON game records.
  # Loaded from read/ or write/, whichever has the higher seq; a file that
  # doesn't end in 'end' (or has any unparseable line) is ignored wholesale.
  # Hand edits: keep the format, bump seq so this copy wins; comments are
  # not preserved.
  seq N
  # own opp mask(hex) wins losses (fractional = model-discounted; ? = unknown opp)
  T Z 0x00000008 3 1.5  # 2FactVult          <- "%c %c 0x%08x %s %s  # %s", numbers with trailing zeros trimmed
  ...
  # record: W-L (xx.x% winrate, N games)        <- overall; per-race lines "#   %c vs %c: ..." if >1 matchup
  # next-pick probabilities, T vs Z (post-update, 10000 Thompson draws):
  #   12.3%  2FactVult        3-1.5
  {"t":"start",...}                              <- every JSON record, one per line
  {"t":"end",...}
  end
  ```
- After onEnd crediting, every arm of the race's table is inserted with 0/0 if missing, so the file
  always lists all arms.

### 4.5 Credit from `win_final` (onEnd `FUN_63f8a090`) [V]

`win_final` is the last `resp.win` received (`DAT_63ff1304`); `DAT_63ff1308` says whether one was ever
received.

| condition | credit |
|---|---|
| no win value ever received | isWinner ? 1 : 0 |
| win_final < -1 | 0 |
| win_final > 1 | 1 |
| reported win, win_final ≥ 0 | 1 |
| reported win, win_final < 0 | (win_final+1)/2 |
| reported loss, win_final ≤ 0 | 0 |
| reported loss, win_final > 0 | (win_final+1)/2 |

- Whenever the credit contradicts the reported result, the DLL logs
  `"BWRL: reported %s but win_final %+.2f -> bandit credit %.3f"`, and the end record carries
  `"discounted":true`.
- The update is `wins += credit` and `losses += 1 - credit`, with credit clamped to [0,1], on
  `stats[matchup][chosen_mask]`.
- It happens only if a pick was made (`DAT_63ff1718`) and the matchup is ≥ 0. The flag is then cleared,
  so a game is credited once.
- Rationale [I]: a crash, disconnect or odd result that disagrees with the model's own final estimate
  is only partly trusted.
- `FUN_63f88b60` then recomputes the "next-pick probabilities" block. It runs 10000 Thompson rounds with
  the same α/β, twin pooling and prior as §4.3, and counts the argmax frequency per arm.

---

## 5. Resign logic and JSON game records

### 5.1 Resign (end of `FUN_63f8a9f0`, disassembly 0x63f8b0d0..0x63f8b1eb) [V]

After every applied step with `frame > 5759` (0x167F, about 4 minutes of game time), and with the
compile-time switch `FUN_63f81660()` returning 1:

- `win > -0.95` (`DAT_63fdaa14`): reset the streak start (`DAT_63fd2134 = -1`).
- else: start the streak if not started. If `frame - streak_start ≥ 240` (> 0xEF, 10 s at 24 fps):
  - log `"BWRL: F%d win=%.3f <= %.2f since F%d (%d frames); gg"`;
  - send chat `"gg"`;
  - `DAT_63fd2108 = frame + 96` (0x60);
  - write an `event` record with `what: "resign"` and detail `"win %.3f <= %.2f for %d frames"`.
- onFrame then calls `Game::leaveGame()` (vtable +0x100, `FUN_63f81630`) once `frame ≥ DAT_63fd2108`,
  and sets `DAT_63ff1660` (`resigned`).
- The minimum win value and its frame are also tracked as `win_min` / `win_min_frame`.

### 5.2 Records (built by `FUN_63f845e0`; fields added by `FUN_63f83f80` for strings and `FUN_63f828b0` for ints) [V keys, [I] some value sources]

Every record starts `{"t":"<type>","id":<n>,"date":"YYYY-MM-DDTHH:MM:SSZ"` (UTC, `gmtime(time())`).
- `id` is the bandit-file `seq` that the game's start record produced (`DAT_63fd2110`). It ties the
  start, event and end records of one game together.
- Records have newlines replaced by spaces and are capped at 4000 characters (`FUN_63f83a70`).

- **start**: `opp, own_race, opp_race ("hidden" when unknown), map, bo, mask ("0x%x"), arms,
  arm_w, arm_l (%g), mode ("block"|"straddle"|"lockstep"), budget_ms (%.2f), dll ("Sep 22 2026")`.
  After that come either `fatal` (engine not up) or `model, ckpt, engine, fps, max_units, transport ("shm"|"pipe")`.
- **event**: `frame` (the last processed frame), `what` ∈ {`fatal`, `resign`, `degraded`,
  `latency_mismatch`}, and `detail` (a message; omitted when empty).
- **end**, fields in this order:

| Field | Source |
|---|---|
| `opp` | |
| `result` | "win" or "loss" |
| `credit` | %g |
| `discounted` | true, only when present |
| `resigned` | bool |
| `frames` | |
| `steps` | |
| `infer_avg_ms`, `infer_max_ms` | |
| `slip` | [s0,s1,s2,s3+] |
| `max_slip` | |
| `reval_steps`, `stale_units`, `stale_max` | |
| `blocked_steps`, `block_avg_ms`, `block_max_ms` | |
| `over47`, `over55`, `max_frame_ms` | |
| `degraded` | |
| `win_final`, `win_min`, `win_min_frame` | |
| `win_traj` | [..] (%.2f values from the (frame, win) trajectory) |

  The trajectory is stored as (frame, win) pairs (`DAT_63ff114c`). When it passes 4096 pairs it is
  decimated 2:1, so memory stays bounded and the trace covers the whole game. The same trajectory
  feeds the `BWRL_DRAW` on-screen graph (box 0x1A4..0x26C × 0x20..0x70).
- onEnd also logs the summary lines `"BWRL: %s summary: ..."`, `"made the game wait on ..."` and
  `"acted on a later frame ..."`.

---

## 6. Error and fatal handling [V]

### 6.1 Sources

- **Launch failure.** CreatePipe, CreateProcess, handshake timeout, early exit, bad magic or version,
  and a max_units cap violation. There are up to 9 attempts with 750 ms spacing, and non-retryable
  errors stop early.
- **Mid-game I/O failure.** Pipe read or write errors, the engine process dying while a response is
  pending (`WaitForMultipleObjects` index 1), a shm wait error, and `num_units` out of range.
- All of these go through `FUN_63f85a70`, which:
  1. builds `"engine connection lost (%s)"` plus `"; engine log: <last line of pluto_infer.log>"`;
  2. formats `"Pluto: %s: %s"` into `DAT_63ff1180`;
  3. logs `"BWRL: %s"`;
  4. clears `DAT_63ff1661` (engine up);
  5. writes an `event` record with `what: "fatal"`.

### 6.2 Fatal state machine (onFrame)

1. The first frame with `DAT_63ff1180` set sends the fatal message to chat in chunks of 64 characters
   or fewer, then `"Pluto: quitting in 10 seconds"`, and sets `DAT_63fd2108 = frame + 240`.
2. At `frame ≥ DAT_63fd2108`: `FUN_63f81670()` is a compile-time switch that returns 1. The DLL logs
   `"BWRL: exiting process after fatal report"` and calls **`TerminateProcess(GetCurrentProcess(), 1)`**,
   so the StarCraft process exits and a tournament manager scores a crash, not a loss.
3. The `"BWRL: fatal; leaving the game"` path (leaveGame instead) exists but is unreachable with this
   build's switch.

No model steps are sent while fatal. The engine, if it is still alive, exits on the parent-handle wait
or the quit flag.

### 6.3 Non-fatal diagnostics

- **Action-latency probe**, during the first 240 frames. It records (unit, issue frame, apply frame)
  samples, and each sample is logged as `"BWRL: latency sample: ..."`.
  - Mode = 4, or no samples: `"action latency OK"` (after ≥ 8 samples) or
    `"latency probe: no samples in the opening window"`.
  - Otherwise it logs `"action latency MISMATCH: measured %d frames, trained for %d"`, sends a chat
    warning, writes an `event` record with `what: "latency_mismatch"`, and plays on "with the
    effect-age off".
  - The trained value is 4 [V constant; meaning of "effect-age" I].
- **Observation sanity.** `"WARNING: continuous[%d][%d] = %.3f (unit type %d)"` and the `global`
  warning clamp values to [-5,5]. `"unit_type ... out of range"` and `"order_type ... out of range"`
  throw inside the builder. These go to stderr (the StarCraft console), not to pluto.log.
- **DLL log.** `pluto.log` is opened lazily by `FUN_63f83910` / `FUN_63f83870` in the CWD and flushed
  after every line.

---

## 7. Open points / not verified

- The semantics of the per-unit int columns (6 × i64), the two per-unit byte arrays, the 20- and
  233-element flag arrays, the two 128×128 maps, and `hist[4]`. The sizes are verified; the meanings
  are not.
- Whether `resp.arg` is always a unit or tech type. The decoder `FUN_63faf4b0` / `FUN_63fadf10`
  dispatches on `a` (e.g. a ∈ 1..4, 7, 16, 17..19, and bitmask 0x9060 for position actions), but its
  semantics were not traced here.
- The source of the prior numbers in the arm tables (presumably offline self-play evaluation).
