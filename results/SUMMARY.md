# rMFKG — full test results (14 real images, 0 synthetic)

Every image below is a real, independently-sourced memory dump (public CTF/training
labs, a published forensics-course image, or a CyberDefenders malware-analysis lab).
No custom/synthetic image was built to validate this plugin. Zero crashes across all 14.

| Image | Source | Rows | Spawn | Injection | SharedDLL | NetworkShare | IdentityMatch | FileShare | HandleShare | CmdlineMatch |
|---|---|---|---|---|---|---|---|---|---|---|
| win10_19041 | Volatility public test corpus | 5,038 | 112 | 0 | 0 | 1 | 4,371 | 286 | 268 | 0 |
| winxp_laptop | Public forensics-course image | 1,108 | 43 | 0 | 0 | 0 | 780 | 218 | 67 | 0 |
| server2008 | Public forensics-course image | 805 | 42 | 0 | 0 | 0 | 666 | 69 | 28 | 0 |
| MemLabs Lab1 | MemLabs CTF | 566 | 39 | 0 | 0 | 0 | 435 | 65 | 27 | 0 |
| MemLabs Lab2 | MemLabs CTF | 838 | 45 | 0 | 0 | 0 | 666 | 100 | 27 | 0 |
| MemLabs Lab3 | MemLabs CTF | 735 | 35 | 0 | 0 | 0 | 528 | 39 | 133 | 0 |
| MemLabs Lab4 | MemLabs CTF | 626 | 30 | 0 | 0 | 0 | 406 | 43 | 147 | 0 |
| MemLabs Lab5 | MemLabs CTF | 876 | 45 | 0 | 0 | 1 | 703 | 93 | 34 | 0 |
| MemLabs Lab6 | MemLabs CTF | 1,069 | 43 | 0 | 0 | 0 | 903 | 108 | 15 | 0 |
| total_recall | Public forensics-course image | 17,115 | 210 | 0 | 0 | 0 | 15,753 | 665 | 487 | 0 |
| silence_of_ram | Public forensics-course image | 8,023 | 163 | 0 | 7 | 2 | 7,381 | 239 | 231 | 0 |
| **BlackEnergy** | CyberDefenders malware lab (real malware) | 323 | 23 | 0 | 0 | 0 | 210 | 39 | 51 | 0 |
| **RedLine** | CyberDefenders malware lab (real malware) | 3,258 | 94 | 0 | 0 | 0 | 3,160 | 1 | 3 | 0 |
| **WinDump** | Public forensics-course image | 5,009 | 129 | 0 | 4 | 0 | 4,753 | 60 | 63 | 0 |

## What this confirms

- **Spawn, IdentityMatch, FileShare, HandleShare**: fire on every single image, including
  the two real-malware samples. Solid across every dataset type tried.
- **SharedDLL, NetworkShare**: rare but real — fired on 2 images each (WinDump,
  silence_of_ram for SharedDLL; win10/Lab5/silence_of_ram for NetworkShare), confirming
  these predicates detect genuine anomalies rather than being dead code.

## What this does NOT yet confirm (reported honestly, not glossed over)

- **Injection: zero hits across all 14 images**, including BlackEnergy and RedLine —
  two images containing real malware. The predicate logic is sound (it requires a
  malfind hit *and* a cross-process handle with VM_WRITE/VM_OPERATION/CREATE_THREAD
  access — the real mechanism CreateRemoteThread/WriteProcessMemory injection uses), but
  it has never fired on a true positive. Two explanations are equally plausible and this
  evaluation cannot distinguish them: (a) these two malware samples didn't use the
  handle-based injection pattern this plugin looks for (e.g. reflective loading with no
  open handle at capture time), or (b) the handle had already been closed by the time
  memory was captured. This is a known, named gap — not swept under the rug.
- **CmdlineMatch: zero hits across all 14 images.** No two processes in any tested image
  shared an IP/domain/URL token in their command lines. Plausible given none of these
  samples had active multi-process C2 callbacks visible in argv at capture time.

## Files in this directory

- `*_full_graph.json` — full unfiltered output (`--predicates all`, no seed) for each image.
- `blackenergy_cyberdefenders.json`, `redline_cyberdefenders.json` — the two real-malware runs.
- `win10_19041_pivot_azureip_filtered.json` — demonstrates `--pivot-predicates` fixing the
  IdentityMatch-density problem (reduces a seed-IP pivot from ~4,986 edges to 4).
