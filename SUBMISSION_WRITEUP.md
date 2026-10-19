# rMFKG — Volatility Foundation 14th Annual Plugin Contest Submission

## What it is

rMFKG (relational Memory Forensics Knowledge Graph) is a Volatility 3 plugin
(`windows.rmfkg.Rmfkg`) that links every process in an image into a single typed
relational graph, instead of leaving an analyst to manually cross-reference the
per-process output of `pslist`, `malfind`, `dlllist`, `netscan`, `getsids`, `handles`,
and `cmdline` by hand. Based on "Formalizing Cross-Process Relationships in Volatile
Memory for Graph-Based Malware Detection" (Addai et al., IEEE QRS 2026); this
submission implements the paper's graph construction using only data Volatility3
already exposes — the paper's GPT-4 threat-intelligence layer is out of scope.

## How it's used

    vol -p ./plugin -f image.dmp windows.rmfkg.Rmfkg [--predicates all|paper5] \
        [--seed-pid N | --seed-ip IP[:PORT] | --seed-dll NAME | --seed-sid SID | \
         --seed-file PATH | --seed-cmdline TEXT] [--max-hops N] \
        [--pivot-predicates Predicate,...] [--max-severity N] [--show-isolated]

With no seed, it reports the full 8-predicate graph. With a seed — a known-bad IP,
file, DLL, SID, or cmdline indicator — it pivots outward via BFS to that indicator's
whole connected subgraph in one pass, instead of five separate manual plugin runs.
Full usage, the predicate table, and the severity ranking are in the README.

## Why it should win

1. **It turns five single-process plugins into one cross-process answer.** An analyst
   who has one IOC (a malicious IP, file, or DLL) gets every other process sharing that
   same attribute in one query, with a BFS pivot that respects hop limits and can be
   restricted to specific predicate types to stay tight on dense graphs.

2. **A real design flaw was found and fixed with before/after evidence, not assumed
   away.** On images where nearly every process shares one SYSTEM-level SID, the
   IdentityMatch predicate alone merges almost the entire process tree into one
   component — a seeded pivot on a real IP returned ~4,986 edges, nearly the whole
   graph, defeating the point of pivoting. Fixed by adding `--pivot-predicates`, which
   restricts which edge types the BFS traverses (edges of other types are still
   reported for pairs that remain in the kept subgraph). Verified reducing that same
   pivot to exactly 4 edges — the two actually relevant processes
   (`results/win10_19041_pivot_azureip_filtered.json`).

3. **Three real false-positive bugs were found and fixed on real images, with
   before/after row counts, not invented or assumed:** bare device/infrastructure
   objects (`\Device\KsecDD`, Hyper-V `vmic*` sync objects, COM registration caches)
   being misclassified as meaningful shared files/handles; a regex anchoring bug
   letting a bare `\Windows\System32` handle slip past the system-path exclusion; and
   SharedDLL's original "anything outside System32" criterion flagging every
   legitimate multi-process app (browsers, antivirus) — replaced with the paper's own
   literal "anomalous load path" criterion (Temp/AppData/Downloads-style, not simply
   non-system). Each fix is documented in the plugin's code comments with the
   reasoning, not silently folded in.

4. **Verified against two real CyberDefenders malware-analysis labs, not just CTF/
   teaching images** — BlackEnergy and RedLine — alongside 12 other real, independently
   sourced images (MemLabs' six labs, public forensics-course dumps, the Volatility test
   corpus). 14 images total, 0 synthetic, 0 crashes.

5. **Honest reporting of what the evaluation does and doesn't confirm.** Spawn,
   IdentityMatch, FileShare, and HandleShare fire on every single image including both
   malware samples. SharedDLL and NetworkShare each confirmed on two independent images.
   But **Injection and CmdlineMatch have zero confirmed true positives across all 14
   images, including the two real-malware samples** — stated plainly in the README and
   `results/SUMMARY.md`, with the two competing explanations (wrong injection technique
   for this detection pattern, vs. evidence already gone by capture time) named rather
   than glossed over. Nothing here was retuned to manufacture a better number.

## Severity ranking and isolated-process reporting

Two triage aids added after initial validation, based on what actually showed up
across the 14-image evaluation: every image's IdentityMatch predicate accounts for
80-95% of row volume, burying the rarer, higher-value edges. A `Severity` column
(1=Injection...8=IdentityMatch) now sorts output by investigative priority, and
`--max-severity` lets an examiner filter noise on demand — nothing is removed from the
underlying graph, only from what's displayed. `--show-isolated` separately surfaces
processes with zero relational edges at all (orphaned: ppid missing from pslist;
isolated: present but connected to nothing) — invisible to any pivot, and themselves a
signal worth an examiner's attention (DKOM-unlinked or hollowed processes often look
exactly like this).

## Repository

Plugin, 16 passing unit tests, full 14-image evaluation and results, README with the
predicate table and honest scope notes: see `README.md` and `results/SUMMARY.md` in
this submission.

## License

Not yet finalized — rMFKG's license will be determined pending the outcome of this
contest, per the repository README.
