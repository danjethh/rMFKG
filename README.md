# rMFKG — Cross-Process Relational Memory Forensics Graph (Volatility 3 plugin)

Based on "Formalizing Cross-Process Relationships in Volatile Memory for Graph-Based
Malware Detection" (Addai et al., IEEE QRS 2026). This plugin implements the paper's
cross-process relational graph construction using **only** data Volatility3 already
exposes — the paper's GPT-4 threat-intelligence layer is **out of scope** for this
submission; this is a straight Volatility plugin.

## Idea

Volatility3 plugins (`pstree`, `malfind`, `dlllist`, `netscan`, `getsids`, `handles`,
`cmdline`) each report **one process's** artifacts in isolation. If an analyst
attributes an IP, a file, a DLL, or a process to malicious activity, there is no
built-in way to find every *other* process sharing that same attribute without
manually re-running and cross-referencing several plugins by hand.

`windows.rmfkg.Rmfkg` builds all processes into a single typed graph, so a known-bad
seed (an IP, a SID, a DLL, a file, a PID, or a cmdline indicator) can be **pivoted**
outward to its whole connected subgraph in one pass.

## Predicates

The paper's 5 (Table I), plus 4 added here using other standard Volatility3 plugins
(toggle with `--predicates paper5` to match the paper exactly). **Severity** is this
plugin's own investigative-value ranking (1 = highest triage priority, 8 = lowest) —
it does not remove or hide anything by default; see `--max-severity` below.

| Severity | Predicate | Fires when | Plugin |
|---|---|---|---|
| 1 | Injection | `pj` has a malfind hit, `pi` holds a Process handle to `pj` with VM_WRITE/VM_OPERATION/CREATE_THREAD access | malfind + handles |
| 2 | NetworkShare | `pi`, `pj` both connect to the same remote IP:port | netscan |
| 3 | CmdlineMatch *(added)* | `pi`, `pj` command lines share an IP/domain/URL indicator | cmdline |
| 4 | SharedDLL | `pi`, `pj` both loaded the same DLL from an anomalous (Temp/AppData/Downloads-style) path | dlllist |
| 5 | HandleShare *(added)* | `pi`, `pj` both hold a handle to the same Mutant/Section object | handles |
| 6 | FileShare *(added)* | `pi`, `pj` both hold an open handle to the same file | handles |
| 7 | Spawn | `pj.ppid == pi.pid` | pstree/pslist |
| 8 | IdentityMatch | `pi`, `pj` share a privileged SID (SYSTEM/Admins/Domain Admins) | getsids |

IdentityMatch is ranked lowest because it is near-universal on any multi-service
Windows box (every SYSTEM-level process shares it) and accounts for 80-95% of row
volume on every image tested — but it is never dropped by default, since it is real
evidence (e.g. token theft) on the rare occasion it's the interesting edge.

**Honest note on Injection:** the paper describes malfind as carrying an `owner_pid`
field identifying the injecting process. Volatility3's real malfind output has no such
field — a VAD only records which process *hosts* a region, not who wrote into it. This
plugin attributes injection direction from a real, available signal instead: a
Process-type handle from `pi` to `pj` carrying VM_WRITE/VM_OPERATION/CREATE_THREAD
access (what WriteProcessMemory/CreateRemoteThread-style injection actually requires).
A malfind hit with no such handle is still visible in the output as an unattributed
finding, but produces no Injection edge. Reported plainly, not retuned to match the
paper's assumed field. **This predicate has not fired on any of the 14 real images
tested, including two real-malware samples** — see `results/SUMMARY.md` for the honest
discussion of why.

## Usage

    vol -p ./plugin -f image.dmp windows.rmfkg.Rmfkg [--predicates all|paper5] \
        [--pid N ...] \
        [--seed-pid N | --seed-ip IP[:PORT] | --seed-dll NAME | --seed-sid SID | \
         --seed-file PATH | --seed-cmdline TEXT] [--max-hops N] \
        [--pivot-predicates Predicate,Predicate,...] \
        [--max-severity N] [--show-isolated]

No seed → full graph (every typed edge found). With a seed → BFS pivot from the
matching process(es) to the connected subgraph only, capped at `--max-hops` if given.

- `--pivot-predicates` restricts which predicate types the BFS *traverses* when
  pivoting (edges of other types are still reported for any pair that stays in the
  resulting subgraph). Needed because on images where nearly every process shares one
  SYSTEM-level SID, Spawn/IdentityMatch can merge most of the process tree into one
  giant component, defeating the point of a pivot — e.g.
  `--pivot-predicates Injection,NetworkShare,SharedDLL` keeps the pivot tight.
  Demonstrated reducing a seed-IP pivot on a real image from ~4,986 edges to 4
  (`results/win10_19041_pivot_azureip_filtered.json`).
- `--max-severity N` hides edges with a Severity rank above N (e.g. `--max-severity 6`
  drops Spawn/IdentityMatch noise, leaving only the rarer high-value predicates). Opt-in,
  off by default — nothing is hidden unless asked for.
- `--show-isolated` switches the output to a *different* table: processes with **zero**
  edges under the current predicate set/pid filter, i.e. processes sharing no
  relationship at all with any other process. Distinguishes `orphaned` (its ppid isn't
  in pslist — a classic DKOM/process-hollowing signal) from `isolated` (present, shares
  nothing). An isolated process is structurally invisible to any pivot, and that absence
  of normal relationships is itself worth an examiner's attention.

Output (default mode) is a standard TreeGrid: one row per edge (SrcPID/Process,
Predicate, **Severity**, DstPID/Process, MultiTypePair, Evidence), sorted by Severity
first. `MultiTypePair=true` marks a process pair linked by two or more predicate types
simultaneously — the paper's "compound attack behavior" signal, worth triaging first.

## Testing

Read-only; never modifies the source image; no synthetic/custom test images used —
only existing, independently documented public memory images (including two real
CyberDefenders malware-analysis labs: BlackEnergy, RedLine).

- `tests/test_rmfkg_logic.py` — 16 unit tests of predicate evaluation, pivot BFS, severity
  filtering, and isolated-process detection against hand-built process graphs (no image
  needed), same approach as PEVAD's test suite.
- Image-level: **14 real images tested, 0 crashes.** Full results and an honest
  discussion of what each predicate has and hasn't been confirmed on:
  see `results/SUMMARY.md`.

## Scope notes / future work (reported honestly, not score-chased)

- The paper's O(n²) pairwise predicate evaluation is used as-is; the paper's own
  inverted-index optimization is not implemented (not needed below ~500 processes).
- RegistryPersistence and remote-thread-level injection sub-typing (paper's own named
  "future work" items: named pipes, shared memory, registry coordination) are not yet
  implemented.
- ParentPIDSpoof detection (catching PPID-spoofing malware that defeats the plain
  Spawn predicate) is a natural v2 addition, not yet built.
- **Injection and CmdlineMatch have zero confirmed true positives across all 14 images
  tested** (see `results/SUMMARY.md`) — the logic is sound but empirically unvalidated
  on a real positive. Not fixed by retuning; would need an image that actually contains
  live cross-process injection or multi-process C2 callbacks with evidence still present
  at capture time.
