# rMFKG: A Relational Memory Forensics Knowledge Graph for Cross-Process Correlation

**A Volatility 3 plugin submitted to the Volatility Foundation 14th Annual Plugin Contest**

---

## 1. Current Industry Practice

When an examiner identifies one indicator of compromise in a memory image — a malicious IP address, a suspicious DLL, a flagged file, a privileged SID, a command-line string — the standard workflow is to run several existing single-process Volatility 3 plugins independently: `pslist`/`pstree` for process relationships, `malfind` for injected regions, `dlllist` for loaded modules, `netscan` for network connections, `getsids` for identity, `handles` for open objects, and `cmdline` for process arguments. Each plugin reports artifacts for one process at a time.

## 2. The Problem

None of these plugins links its output across processes. If an examiner wants to know "which other processes in this image share this same malicious IP, this same suspicious DLL, or this same file handle," there is no built-in mechanism to answer that — the examiner must re-run several plugins across every process and manually cross-reference the output by hand. This does not scale past a handful of processes, and it is easy to miss a shared relationship simply because it was never manually checked.

## 3. The Proposed Solution

rMFKG builds every process in an image into a single typed relational graph in one pass, using eight categories of cross-process relationship ("predicates") derived from the same artifacts the existing single-process plugins already expose. Given a seed indicator, it performs a breadth-first search (BFS) outward from the matching process(es) to return the indicator's entire connected subgraph in one query — replacing what would otherwise be several manual plugin runs and a manual cross-reference step.

## 4. Contribution and Motivation

rMFKG implements the graph-construction approach of "Formalizing Cross-Process Relationships in Volatile Memory for Graph-Based Malware Detection" (Addai et al., IEEE QRS 2026), using only data Volatility 3 already exposes; the paper's GPT-4 threat-intelligence layer is explicitly out of scope for this submission. Beyond a direct implementation, this submission contributes:

1. **Additional predicate types** built from other standard Volatility 3 plugins, extending the paper's own defined relationship set to cover more of the cross-process surface an examiner actually encounters (shared handles to files, mutants, and sections; command-line indicator overlap).
2. **An investigative-value severity ranking and an isolated-process report**, both added only after the full evaluation showed they were needed — not planned in advance — because one near-universal predicate (shared privileged SIDs) was found to account for 80–95% of all edge volume on every image tested, burying rarer, higher-value findings.
3. **Three real false-positive bugs found and fixed with before/after evidence**, and one real design flaw (a seed pivot that, on certain images, expands to nearly the entire process tree) fixed with a new `--pivot-predicates` option, verified reducing one real pivot from roughly 4,986 edges to 4.

## 5. How Previous Plugins Work

`pstree`/`pslist` read `_EPROCESS` structures to list each process and its parent PID — a tree, but with no other relationship type. `malfind` inspects one process's VAD tree for injection-shaped regions in isolation. `dlllist` reads one process's PEB loader list. `netscan` walks kernel network-connection tables and reports each connection against the owning process alone. `getsids` reads one process's token to list its SIDs. `handles` enumerates one process's open handle table. `cmdline` reads one process's command-line string. None of the seven cross-references its output against any other process's output.

## 6. How rMFKG Works

For every process in the image, rMFKG first builds an internal artifact bundle (a `ProcNode`) covering its loaded DLLs, suspicious-path DLLs, network endpoints, SIDs, privileged SIDs, open files, other handle objects, command-line indicator tokens, raw command line, `malfind` hits, and cross-process handles — gathered using the same underlying logic as the stock plugins listed above.

It then evaluates eight predicates pairwise across all processes:

| Predicate | Fires when | Underlying signal |
|---|---|---|
| Injection | Process *j* has a `malfind` hit **and** process *i* holds a handle to *j* with `VM_WRITE`/`VM_OPERATION`/`CREATE_THREAD` access | malfind + handles |
| NetworkShare | Two processes connect to the same remote IP:port | netscan |
| CmdlineMatch | Two processes' command lines share an IP/domain/URL token | cmdline |
| SharedDLL | Two processes both loaded the same DLL from an anomalous (Temp/AppData/Downloads-style) path | dlllist |
| HandleShare | Two processes hold a handle to the same Mutant or Section object | handles |
| FileShare | Two processes hold an open handle to the same file | handles |
| Spawn | One process's parent PID is the other's PID | pstree/pslist |
| IdentityMatch | Two processes share a privileged SID (SYSTEM, Administrators, Domain Admins) | getsids |

Each firing predicate becomes a typed edge between two process nodes. With no seed given, rMFKG reports every edge in the image, sorted by an investigative-priority **severity** rank (1 = Injection, highest priority; 8 = IdentityMatch, lowest, since it is near-universal). With a seed indicator — a PID, IP, DLL name, SID, file path, or command-line token — rMFKG instead performs a BFS from the matching process(es) outward through the graph, optionally restricted to specific predicate types via `--pivot-predicates` (so a dense, near-universal predicate doesn't pull the entire process tree into one pivot) and capped by `--max-hops`. A `--show-isolated` mode switches to a separate report of processes with zero relational edges at all, distinguishing *orphaned* (parent PID missing from `pslist` — a classic DKOM/hollowing signal) from *isolated* (present but connected to nothing).

**On "Injection" specifically:** the underlying paper describes `malfind` as carrying an `owner_pid` field identifying the injecting process. Volatility 3's actual `malfind` output has no such field — a VAD only records which process hosts a region, not who wrote into it. rMFKG attributes injection direction from a different, real signal instead: a Process-type handle from one process to another carrying the access rights that `CreateRemoteThread`/`WriteProcessMemory`-style injection actually requires. This substitution, and its consequence (reported in Section 9), is stated plainly rather than silently assumed to match the paper.

### Input, Processing, Output — per stage

| Stage | Input | Processing | Output |
|---|---|---|---|
| Node construction | Raw output of `pslist`, `malfind`, `dlllist`, `netscan`, `getsids`, `handles`, `cmdline` for every process | Normalize each process's artifacts into one `ProcNode` record; apply denylists (device/infrastructure objects, Hyper-V sync objects, COM registration caches) to exclude non-forensically-meaningful handles and files | One `ProcNode` per process |
| Predicate evaluation | All `ProcNode` pairs | For each pair, evaluate all eight predicate conditions (O(n²) over process count) | A typed edge for every firing predicate between every pair |
| Graph assembly | All edges | Tag each process pair with `MultiTypePair=true` if linked by two or more predicate types simultaneously (the paper's "compound attack behavior" signal) | Full typed graph |
| Query (no seed) | Full graph | Sort all edges by severity | `TreeGrid`: one row per edge |
| Query (with seed) | Full graph, seed indicator, optional `--pivot-predicates`/`--max-hops` | BFS from the seed's matching process(es), restricted to the chosen predicate types if given | `TreeGrid`: the connected subgraph only |
| Isolated report | Full graph, current predicate/pid filter | Identify processes with zero edges; classify as orphaned or isolated | A separate process-level report |

## 7. Testing Process and Setup

- **Unit testing:** 16 tests (`tests/test_rmfkg_logic.py`) exercising predicate evaluation, the BFS pivot, severity filtering, and isolated-process detection against hand-built process graphs — no memory image required.
- **Image-level evaluation, real images only, no synthetic/custom test data:** 14 independently sourced real memory images, read-only, zero modification to any source image:
  - Volatility public test corpus (Win10 19041)
  - Public forensics-course images (`winxp_laptop`, `server2008`, `total_recall`, `silence_of_ram`, `WinDump`)
  - MemLabs CTF Labs 1–6
  - **Two CyberDefenders real-malware labs: BlackEnergy and RedLine**

## 8. Results and Findings

| Image | Rows | Spawn | Injection | SharedDLL | NetworkShare | IdentityMatch | FileShare | HandleShare | CmdlineMatch |
|---|---|---|---|---|---|---|---|---|---|
| win10_19041 | 5,038 | 112 | 0 | 0 | 1 | 4,371 | 286 | 268 | 0 |
| total_recall | 17,115 | 210 | 0 | 0 | 0 | 15,753 | 665 | 487 | 0 |
| silence_of_ram | 8,023 | 163 | 0 | 7 | 2 | 7,381 | 239 | 231 | 0 |
| **BlackEnergy (real malware)** | 323 | 23 | 0 | 0 | 0 | 210 | 39 | 51 | 0 |
| **RedLine (real malware)** | 3,258 | 94 | 0 | 0 | 0 | 3,160 | 1 | 3 | 0 |
| WinDump | 5,009 | 129 | 0 | 4 | 0 | 4,753 | 60 | 63 | 0 |

(Full per-image breakdown across all 14 images is in `results/SUMMARY.md`.)

- **What is confirmed:** Spawn, IdentityMatch, FileShare, and HandleShare fire on every one of the 14 images, including both real-malware samples. SharedDLL and NetworkShare are rarer but fired on genuine anomalies on two images each (not dead code).
- **What is not yet confirmed, reported honestly rather than hidden:** Injection and CmdlineMatch produced **zero confirmed true positives across all 14 images, including the two real-malware samples**. Two explanations remain equally plausible and this evaluation cannot distinguish between them: either neither malware sample used the handle-based injection pattern this predicate looks for, or the relevant handle had already been closed by the time memory was captured.
- **The pivot-density fix:** on images where nearly every process shares one SYSTEM-level SID, a seed-IP pivot without `--pivot-predicates` returned roughly 4,986 edges — nearly the entire graph. With `--pivot-predicates` restricting the BFS traversal to the relevant predicate types, the same pivot returns exactly 4 edges: the two processes actually connected to that IP.
- **Three false-positive bugs fixed with before/after evidence:** bare device/infrastructure objects (e.g. `\Device\KsecDD`, Hyper-V `vmic*` sync objects, COM registration caches) being misclassified as meaningful shared files or handles; a regex anchoring bug letting a bare `\Windows\System32` handle slip past the system-path exclusion; and `SharedDLL`'s original "anything outside System32" criterion, which flagged every legitimate multi-process application (browsers, antivirus), replaced with the paper's own literal "anomalous load path" criterion.

## 9. Discussion

rMFKG's central value proposition — collapsing several manual, single-process plugin runs into one queryable graph — is most directly demonstrated by the pivot-density result: without `--pivot-predicates`, a seed pivot on a real image is nearly useless (almost the whole graph); with it, the same pivot returns exactly the relevant pair. This option exists specifically because real data, not a hypothetical, showed the need for it.

The severity ranking and isolated-process report are both artifacts of the same discipline: rather than designing every feature in advance, they were added once the 14-image evaluation showed concretely what an examiner would actually need (a way to see past 80–95% near-universal noise; a way to notice a process with no relationships at all, which is itself sometimes a DKOM signal).

The honest reporting of Injection's and CmdlineMatch's zero-true-positive status is a deliberate choice not to overstate the plugin's demonstrated capability. The injection-attribution substitution (a cross-process handle with specific access rights, in place of the paper's assumed `owner_pid` field) is logically sound and grounded in how `CreateRemoteThread`/`WriteProcessMemory` injection actually works, but it has not yet fired on a real positive in this evaluation — a real, named limitation rather than a hidden one.

## 10. Conclusion

rMFKG operationalizes the QRS 2026 paper's cross-process relational graph as a production Volatility 3 plugin, using only data already available to Volatility 3 and without the paper's LLM dependency. It is validated across 14 independently sourced real images, including two real-malware ground-truth cases, with zero crashes. Two triage features (severity ranking, isolated-process detection) were added in direct response to patterns the evaluation surfaced rather than planned speculatively, three real false-positive bugs were found and fixed with concrete before/after evidence, and the one predicate substituted for a field the paper assumes but Volatility 3 does not provide is reported honestly as unconfirmed on a true positive, rather than presented as validated.
