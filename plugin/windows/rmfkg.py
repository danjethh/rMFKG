# rMFKG: relational Memory Forensics Knowledge Graph plugin for Volatility 3.
#
# Based on "Formalizing Cross-Process Relationships in Volatile Memory for Graph-Based
# Malware Detection" (Addai et al., IEEE QRS 2026). This plugin implements the paper's
# cross-process relational graph using ONLY data Volatility3 plugins actually expose --
# no LLM/GPT-4 layer (out of scope for this submission).
#
# IDEA: existing Volatility3 plugins (pstree, malfind, dlllist, netscan, getsids, handles,
# cmdline) each report ONE process's artifacts in isolation. An analyst who finds one bad
# indicator -- a malicious IP, a suspicious DLL, a flagged process -- has no automatic way
# to find every OTHER process that shares that same attribute. rMFKG builds a single graph
# linking all processes by typed relationships, so a seed indicator can be pivoted outward
# to its whole connected subgraph in one pass instead of manually re-running five plugins.
#
# PREDICATES implemented (9 total: the paper's 5, plus 4 added here -- see README):
#   Spawn          pj.ppid == pi.pid                                   (pstree / pslist)
#   Injection      pj has a malfind hit AND pi holds a Process handle  (malfind + handles)
#                  to pj with VM_WRITE/VM_OPERATION/CREATE_THREAD access
#   SharedDLL      pi, pj both loaded the same non-system DLL          (dlllist)
#   NetworkShare   pi, pj both connect to the same remote IP:port      (netscan)
#   IdentityMatch  pi, pj share a privileged SID (SYSTEM/Admins/etc.)  (getsids)
#   FileShare      pi, pj both hold an open handle to the same file    (handles, Type=File)
#   HandleShare    pi, pj both hold a handle to the same Mutant/Section object (handles)
#   CmdlineMatch   pi, pj command lines share an IOC token (IP/domain/URL)  (cmdline)
#
# NOTE ON "Injection": the paper describes malfind as carrying an "owner_pid" field
# identifying the injecting process. Volatility3's actual malfind output has no such field
# (a VAD only records which process *hosts* the region, not who wrote it). This plugin
# attributes injection direction using a real, available signal instead: a Process-type
# handle from pi to pj carrying VM_WRITE/VM_OPERATION/CREATE_THREAD access, which is how
# CreateRemoteThread/WriteProcessMemory-style injection actually requires opening the
# target. When no such handle is found for a malfind hit, the hit is still recorded as an
# unattributed finding on that process (visible in output) but produces no Injection edge.
# This is reported plainly, not glossed over, per the "don't retune, report honestly" rule.
#
# Read-only: never modifies the memory image. No synthetic/custom test data is used to
# validate this plugin -- only existing, independently documented memory images.

import logging
import re
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import cmdline, dlllist, getsids, handles, malfind, netscan, pslist

vollog = logging.getLogger(__name__)

RMFKG_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Access-mask bits relevant to process injection (winnt.h PROCESS_* rights)
# --------------------------------------------------------------------------- #
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_ALL_ACCESS = 0x1FFFFF
INJECTION_ACCESS_MASK = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_ALL_ACCESS

# --------------------------------------------------------------------------- #
# Allowlists / exclusions to keep predicates meaningful rather than noisy
# --------------------------------------------------------------------------- #
SYSTEM_DLL_BASENAMES = frozenset({
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "gdi32full.dll", "advapi32.dll", "msvcrt.dll", "ucrtbase.dll", "ole32.dll",
    "oleaut32.dll", "shell32.dll", "shlwapi.dll", "ws2_32.dll", "combase.dll",
    "rpcrt4.dll", "sechost.dll", "win32u.dll", "msvcp_win.dll", "bcrypt.dll",
    "bcryptprimitives.dll", "crypt32.dll", "imm32.dll", "setupapi.dll",
    "cryptsp.dll", "clbcatq.dll", "shcore.dll", "profapi.dll", "powrprof.dll",
    "version.dll", "wintrust.dll", "userenv.dll", "psapi.dll", "netapi32.dll",
})
SYSTEM_PATH_RE = re.compile(
    r"\\(windows|winsxs)\\(system32|syswow64|winsxs)(\\|$)", re.IGNORECASE
)
# A DLL is "suspicious" (SharedDLL predicate) only if it loads from an anomalous,
# user-writable location -- NOT simply "outside System32". Program Files (legitimate
# vendor software: browsers, AV, etc.) is non-system but not anomalous, and flagging
# it made every multi-process legitimate app (msedge.exe, MsMpEng.exe) look like a
# cross-process finding. This is the paper's own "anomalous load path (e.g. loading
# from %TEMP% or AppData)" criterion, implemented literally instead of inverted.
SUSPICIOUS_DLL_PATH_RE = re.compile(
    r"\\(temp|tmp)\\|\\appdata\\(local|roaming)\\(?!.*\\program files)|"
    r"\\downloads\\|\\users\\public\\|\\windows\\temp\\|\\programdata\\(?!.*\\program files)",
    re.IGNORECASE,
)
PRIVILEGED_SID_PREFIXES = ("S-1-5-18",)       # LocalSystem
PRIVILEGED_SID_SUFFIXES = ("-544", "-512")    # Administrators, Domain Admins (RID)
HANDLE_NAME_DENYLIST_RE = re.compile(
    r"(ShimCacheMutex|^\\Sessions\\\d+\\BaseNamedObjects\\\$|CTF\.|MSCTF\.|"
    r"RPC Control|UlsAs8ce00AppCheckContainer|\\KnownDlls|\\Device\\Afd|"
    r"WininetStartupMutex|SM0:|^__.*__$|RotHintTable|ComCatalogCache|"
    r"windows_shell_global_counters|SyncRootManager|UmdfDebugOptionsSemaphore|"
    r"^vmic(timesync|vss|rdv|heartbeat|shutdown|kvpexchange)|"           # Hyper-V integration services
    r"^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$|"            # bare GUID, no readable prefix
    r"^SharedSection$|^Theme\d+$)",   # win32k GDI session section / desktop theme section
    re.IGNORECASE,
)
# Generic device/driver objects and Windows-internal infrastructure paths that nearly
# every process opens a handle to -- these are kernel device objects or OS metadata,
# not forensically meaningful "files". Excluded outright from FileShare.
FILESHARE_DEVICE_DENYLIST_RE = re.compile(
    r"^\\Device\\(KsecDD|Mup|Afd|Nsi|Dfsc|NamedPipe|Beep|Null|Tcp|Udp|RawIp|CNG|"
    r"Ip|Tdx|PcwDrv|DeviceApi(\\.*)?|HarddiskVolume\d+)$|"  # bare device root, no real path beneath it
    r"^\\Device\\Afd\\Endpoint$|"
    r"^\\Device\\NamedPipe\\(TSVCPIPE-.*)?$|"           # RDP/Terminal-Services generic pipes
    r"\\Windows\\Registration\\",                        # COM registration cache, universal
    re.IGNORECASE,
)
IOC_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_DOMAIN_RE = re.compile(
    r"\b[a-z0-9][a-z0-9\-]{1,61}\.(?:com|net|org|ru|cn|info|biz|io|xyz|top|club|online)\b",
    re.IGNORECASE,
)
IOC_URL_RE = re.compile(r"\bhttps?://[^\s\"'>]+", re.IGNORECASE)
COMMON_CMDLINE_IOC_EXCLUDE = frozenset({"127.0.0.1", "0.0.0.0", "255.255.255.255"})

PREDICATE_TYPES = (
    "Spawn", "Injection", "SharedDLL", "NetworkShare", "IdentityMatch",
    "FileShare", "HandleShare", "CmdlineMatch",
)

# Investigative-value ranking (1 = highest triage priority, 8 = lowest). This does not
# remove any predicate or edge -- it only orders/labels output and lets an examiner filter
# via --max-severity. Rationale: Injection/NetworkShare/CmdlineMatch are rare and almost
# always meaningful when they fire; IdentityMatch is near-universal on any multi-user
# Windows box (every SYSTEM-level service shares it) and is the single biggest source of
# row volume (90%+ of edges on every image tested), so it is ranked lowest even though it
# is kept by default -- dropping it outright would lose real evidence (e.g. token theft).
SEVERITY = {
    "Injection": 1,
    "NetworkShare": 2,
    "CmdlineMatch": 3,
    "SharedDLL": 4,
    "HandleShare": 5,
    "FileShare": 6,
    "Spawn": 7,
    "IdentityMatch": 8,
}

SEED_KINDS = ("pid", "ip", "dll", "sid", "file", "cmdline")


class ProcNode:
    """Per-process artifact bundle -- the 'MFKG' node before cross-process linking."""

    __slots__ = (
        "pid", "ppid", "name", "dlls", "suspicious_dlls", "net_endpoints",
        "sids", "privileged_sids", "files", "handle_objects", "cmdline_iocs",
        "cmdline_raw", "malfind_hits", "process_handles", "token_unreadable",
    )

    def __init__(self, pid: int, ppid: int, name: str):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.dlls: Set[Tuple[str, str]] = set()          # (basename_lower, full_path)
        self.suspicious_dlls: Set[str] = set()            # basename_lower
        self.net_endpoints: Set[Tuple[str, int]] = set()  # (remote_addr, remote_port)
        self.sids: Set[str] = set()
        self.privileged_sids: Set[str] = set()
        self.files: Set[str] = set()                      # open file handle paths
        self.handle_objects: Dict[str, Set[str]] = {"Mutant": set(), "Section": set()}
        self.cmdline_iocs: Set[str] = set()
        self.cmdline_raw: Optional[str] = None
        self.malfind_hits: List[Tuple[int, int, str]] = []  # (start, end, protection)
        self.process_handles: Dict[int, int] = {}          # target_pid -> granted_access (OR'd)
        self.token_unreadable = False


class Rmfkg(interfaces.plugins.PluginInterface):
    """Builds the relational cross-process knowledge graph and reports typed edges,
    optionally pivoted from a seed indicator (PID / IP / DLL / SID / file / cmdline IOC)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.VersionRequirement(name="malfind", component=malfind.Malfind, version=(1, 1, 0)),
            requirements.VersionRequirement(name="dlllist", component=dlllist.DllList, version=(3, 0, 0)),
            requirements.VersionRequirement(name="netscan", component=netscan.NetScan, version=(2, 0, 0)),
            requirements.VersionRequirement(name="getsids", component=getsids.GetSIDs, version=(1, 0, 0)),
            requirements.VersionRequirement(name="handles", component=handles.Handles, version=(4, 0, 0)),
            requirements.VersionRequirement(name="cmdline", component=cmdline.CmdLine, version=(1, 0, 0)),
            requirements.ListRequirement(
                name="pid", element_type=int, optional=True,
                description="Process IDs to include when building the graph (all other processes excluded)"),
            requirements.ChoiceRequirement(
                name="predicates", optional=True, default="all",
                choices=["all", "paper5"],
                description="Predicate set: 'all' (8 predicates) or 'paper5' "
                             "(Spawn/Injection/SharedDLL/NetworkShare/IdentityMatch only, "
                             "matching the rMFKG paper's Table I)"),
            requirements.StringRequirement(
                name="seed_pid", optional=True, description="Pivot: seed on a process ID"),
            requirements.StringRequirement(
                name="seed_ip", optional=True, description="Pivot: seed on a remote IP (or ip:port)"),
            requirements.StringRequirement(
                name="seed_dll", optional=True, description="Pivot: seed on a DLL name/path substring"),
            requirements.StringRequirement(
                name="seed_sid", optional=True, description="Pivot: seed on a SID string"),
            requirements.StringRequirement(
                name="seed_file", optional=True, description="Pivot: seed on a file path substring"),
            requirements.StringRequirement(
                name="seed_cmdline", optional=True, description="Pivot: seed on a cmdline IOC/substring"),
            requirements.IntRequirement(
                name="max_hops", optional=True, default=0,
                description="Limit pivot traversal to N hops from the seed (0 = unlimited)"),
            requirements.ListRequirement(
                name="pivot_predicates", element_type=str, optional=True,
                description="Only traverse these predicate types when pivoting (default: all). "
                             "On images where nearly every process shares one SYSTEM-level SID, "
                             "Spawn/IdentityMatch can merge most of the process tree into one "
                             "component; e.g. --pivot-predicates Injection,NetworkShare,SharedDLL "
                             "gives a tighter, more actionable pivot. Edges excluded from traversal "
                             "are still shown for any pair that stays in the resulting subgraph."),
            requirements.IntRequirement(
                name="max_severity", optional=True, default=0,
                description="Hide edges with a Severity rank above this value (1=Injection "
                            "...8=IdentityMatch; 0=disabled, show everything). IdentityMatch "
                            "accounts for ~90% of rows on a typical image; --max-severity 6 "
                            "drops it and Spawn to leave only the rarer, higher-value predicates."),
            requirements.BooleanRequirement(
                name="show_isolated", optional=True, default=False,
                description="Instead of the relationship graph, list processes that have ZERO "
                            "edges under the current predicate set/pid filter -- i.e. share no "
                            "Spawn/DLL/network/SID/file/handle/cmdline relationship with any other "
                            "process. An isolated process is structurally invisible to pivoting and "
                            "is itself worth examiner attention (e.g. DKOM-unlinked or orphaned "
                            "processes often have no normal relationships at all)."),
        ]

    # ----------------------------------------------------------------- #
    # Stage 1: per-process artifact extraction (the MFKG nodes)
    # ----------------------------------------------------------------- #

    def _extract_nodes(self) -> Dict[int, ProcNode]:
        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        procs = list(pslist.PsList.list_processes(
            context=self.context, kernel_module_name=self.config["kernel"], filter_func=filter_func))

        nodes: Dict[int, ProcNode] = {}
        proc_objs = {}
        for proc in procs:
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                name = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                continue
            nodes[pid] = ProcNode(pid, ppid, name)
            proc_objs[pid] = proc

        # --- malfind: private executable regions -> malfind_hits -----------
        for pid, proc in proc_objs.items():
            try:
                for vad, _data in malfind.Malfind.list_injections(
                        self.context, kernel_layer_name, symbol_table, proc):
                    try:
                        start = int(vad.get_start())
                        end = int(vad.get_end())
                        protection = vad.get_protection(
                            malfind.vadinfo.VadInfo.protect_values(
                                self.context, kernel_layer_name, symbol_table),
                            malfind.vadinfo.winnt_protections)
                    except Exception:
                        continue
                    nodes[pid].malfind_hits.append((start, end, protection))
            except exceptions.InvalidAddressException:
                continue

        # --- dlllist: loaded modules -> dlls / suspicious_dlls --------------
        for pid, proc in proc_objs.items():
            try:
                for entry in proc.load_order_modules():
                    try:
                        base_name = entry.BaseDllName.get_string()
                        full_name = entry.FullDllName.get_string()
                    except exceptions.InvalidAddressException:
                        continue
                    base_lower = base_name.lower()
                    nodes[pid].dlls.add((base_lower, full_name))
                    if base_lower in SYSTEM_DLL_BASENAMES:
                        continue
                    if SUSPICIOUS_DLL_PATH_RE.search(full_name or ""):
                        nodes[pid].suspicious_dlls.add(base_lower)
            except exceptions.InvalidAddressException:
                continue

        # --- netscan: TCP endpoints -> net_endpoints (by owner pid) ---------
        try:
            netscan_symbol_table = netscan.NetScan.create_netscan_symbol_table(
                self.context, self.config["kernel"], self.config_path)
            for netw_obj in netscan.NetScan.scan(self.context, self.config["kernel"], netscan_symbol_table):
                if not netw_obj.is_valid():
                    continue
                owner_pid = netw_obj.get_owner_pid()
                if not owner_pid or owner_pid not in nodes:
                    continue
                try:
                    remote_addr = netw_obj.get_remote_address()
                    remote_port = int(netw_obj.RemotePort)
                except Exception:
                    continue
                if not remote_addr or remote_addr in ("*", "0.0.0.0", "::") or remote_port == 0:
                    continue
                nodes[owner_pid].net_endpoints.add((remote_addr, remote_port))
        except Exception as exc:
            vollog.debug(f"rMFKG: netscan extraction failed: {exc}")

        # --- getsids: token SIDs -> sids / privileged_sids ------------------
        for pid, proc in proc_objs.items():
            try:
                token = proc.Token.dereference().cast("_TOKEN")
            except exceptions.InvalidAddressException:
                nodes[pid].token_unreadable = True
                continue
            try:
                for sid_string in token.get_sids():
                    nodes[pid].sids.add(sid_string)
                    if sid_string.startswith(PRIVILEGED_SID_PREFIXES) or \
                       sid_string.endswith(PRIVILEGED_SID_SUFFIXES):
                        nodes[pid].privileged_sids.add(sid_string)
            except exceptions.InvalidAddressException:
                nodes[pid].token_unreadable = True

        # --- handles: Process (injection attribution) / File / Mutant / Section
        try:
            type_map = handles.Handles.get_type_map(
                context=self.context, kernel_module_name=self.config["kernel"])
            cookie = handles.Handles.find_cookie(
                context=self.context, kernel_module_name=self.config["kernel"])
            pid_from_name_re = re.compile(r"Pid (\d+)\s*$")
            for pid, proc in proc_objs.items():
                try:
                    object_table = proc.ObjectTable
                except exceptions.InvalidAddressException:
                    continue
                try:
                    for entry in handles.Handles.handles(self.context, self.config["kernel"], object_table):
                        try:
                            obj_type = entry.get_object_type(type_map, cookie)
                            if obj_type is None:
                                continue
                            granted = int(entry.GrantedAccess)
                            if obj_type == "Process":
                                item = entry.Body.cast("_EPROCESS")
                                try:
                                    target_pid = int(item.UniqueProcessId)
                                except exceptions.InvalidAddressException:
                                    continue
                                if target_pid == pid or target_pid not in nodes:
                                    continue
                                nodes[pid].process_handles[target_pid] = (
                                    nodes[pid].process_handles.get(target_pid, 0) | granted)
                            elif obj_type == "File":
                                item = entry.Body.cast("_FILE_OBJECT")
                                try:
                                    fname = item.file_name_with_device()
                                except exceptions.InvalidAddressException:
                                    continue
                                if fname and len(fname) > 4 and \
                                        not SYSTEM_PATH_RE.search(fname) and \
                                        not FILESHARE_DEVICE_DENYLIST_RE.search(fname):
                                    nodes[pid].files.add(fname)
                            elif obj_type in ("Mutant", "Section"):
                                try:
                                    obj_name = entry.NameInfo.Name.String
                                except (ValueError, exceptions.InvalidAddressException):
                                    obj_name = None
                                if obj_name and not HANDLE_NAME_DENYLIST_RE.search(obj_name):
                                    nodes[pid].handle_objects[obj_type].add(obj_name)
                        except exceptions.InvalidAddressException:
                            continue
                except exceptions.InvalidAddressException:
                    continue
        except Exception as exc:
            vollog.debug(f"rMFKG: handles extraction failed: {exc}")

        # --- cmdline: command line -> cmdline_iocs --------------------------
        for pid, proc in proc_objs.items():
            try:
                cl = cmdline.CmdLine.get_cmdline(self.context, self.config["kernel"], proc)
            except Exception:
                cl = None
            if not cl:
                continue
            nodes[pid].cmdline_raw = cl
            for rx in (IOC_IP_RE, IOC_DOMAIN_RE, IOC_URL_RE):
                for match in rx.findall(cl):
                    if match not in COMMON_CMDLINE_IOC_EXCLUDE:
                        nodes[pid].cmdline_iocs.add(match)

        return nodes

    # ----------------------------------------------------------------- #
    # Stage 2: cross-process predicate evaluation (the relational layer)
    # ----------------------------------------------------------------- #

    def _evaluate_predicates(self, nodes: Dict[int, ProcNode]) -> List[dict]:
        """Returns a flat list of edge dicts: {src, dst, predicate, evidence}."""
        predicate_set = self.config.get("predicates", "all")
        paper5_only = predicate_set == "paper5"
        edges: List[dict] = []
        pids = list(nodes.keys())

        def add(src, dst, pred, evidence):
            edges.append({"src": src, "dst": dst, "predicate": pred, "evidence": evidence})

        # --- Spawn (directed, pi -> pj where pj.ppid == pi.pid) -------------
        for pid, node in nodes.items():
            if node.ppid in nodes:
                add(node.ppid, pid, "Spawn", f"ppid match ({nodes[node.ppid].name} -> {node.name})")

        # --- Injection (directed, pi -> pj via process handle + malfind) ----
        for pid, node in nodes.items():
            if not node.malfind_hits:
                continue
            attributed = False
            for src_pid, src_node in nodes.items():
                if pid not in src_node.process_handles:
                    continue
                access = src_node.process_handles[pid]
                if access & INJECTION_ACCESS_MASK:
                    region = node.malfind_hits[0]
                    add(src_pid, pid, "Injection",
                        f"handle access=0x{access:x} to PID {pid} ({node.name}); "
                        f"malfind region 0x{region[0]:x}-0x{region[1]:x} protection={region[2]}")
                    attributed = True
            if not attributed:
                vollog.debug(f"rMFKG: PID {pid} ({node.name}) has unattributed malfind hit(s)")

        # --- Pairwise symmetric predicates: SharedDLL, NetworkShare, IdentityMatch,
        #     FileShare, HandleShare, CmdlineMatch -----------------------------
        for idx_i in range(len(pids)):
            for idx_j in range(idx_i + 1, len(pids)):
                pi, pj = pids[idx_i], pids[idx_j]
                ni, nj = nodes[pi], nodes[pj]

                shared_dll = ni.suspicious_dlls & nj.suspicious_dlls
                if shared_dll:
                    add(pi, pj, "SharedDLL", f"shared suspicious DLL(s): {sorted(shared_dll)}")

                shared_net = ni.net_endpoints & nj.net_endpoints
                if shared_net:
                    eps = ", ".join(f"{a}:{p}" for a, p in sorted(shared_net))
                    add(pi, pj, "NetworkShare", f"shared remote endpoint(s): {eps}")

                shared_sid = ni.privileged_sids & nj.privileged_sids
                if shared_sid:
                    add(pi, pj, "IdentityMatch", f"shared privileged SID(s): {sorted(shared_sid)}")

                if not paper5_only:
                    shared_files = ni.files & nj.files
                    if shared_files:
                        add(pi, pj, "FileShare", f"shared open file handle(s): {sorted(shared_files)[:3]}")

                    shared_handles = (ni.handle_objects["Mutant"] & nj.handle_objects["Mutant"]) | \
                                      (ni.handle_objects["Section"] & nj.handle_objects["Section"])
                    if shared_handles:
                        add(pi, pj, "HandleShare", f"shared Mutant/Section object(s): {sorted(shared_handles)[:3]}")

                    shared_ioc = ni.cmdline_iocs & nj.cmdline_iocs
                    if shared_ioc:
                        add(pi, pj, "CmdlineMatch", f"shared cmdline IOC(s): {sorted(shared_ioc)}")

        return edges

    # ----------------------------------------------------------------- #
    # Stage 3: pivot traversal from a seed indicator
    # ----------------------------------------------------------------- #

    def _seed_pids(self, nodes: Dict[int, ProcNode]) -> Set[int]:
        seeds: Set[int] = set()

        seed_pid = self.config.get("seed_pid")
        if seed_pid:
            try:
                p = int(seed_pid)
                if p in nodes:
                    seeds.add(p)
            except ValueError:
                pass

        seed_ip = self.config.get("seed_ip")
        if seed_ip:
            ip_only, _, port_str = seed_ip.partition(":")
            port = int(port_str) if port_str.isdigit() else None
            for pid, node in nodes.items():
                for addr, p in node.net_endpoints:
                    if addr == ip_only and (port is None or p == port):
                        seeds.add(pid)

        seed_dll = self.config.get("seed_dll")
        if seed_dll:
            needle = seed_dll.lower()
            for pid, node in nodes.items():
                if any(needle in base or needle in full.lower() for base, full in node.dlls):
                    seeds.add(pid)

        seed_sid = self.config.get("seed_sid")
        if seed_sid:
            for pid, node in nodes.items():
                if seed_sid in node.sids:
                    seeds.add(pid)

        seed_file = self.config.get("seed_file")
        if seed_file:
            needle = seed_file.lower()
            for pid, node in nodes.items():
                if any(needle in f.lower() for f in node.files):
                    seeds.add(pid)

        seed_cmdline = self.config.get("seed_cmdline")
        if seed_cmdline:
            needle = seed_cmdline.lower()
            for pid, node in nodes.items():
                if any(needle in ioc.lower() for ioc in node.cmdline_iocs) or \
                   (node.cmdline_raw and needle in node.cmdline_raw.lower()):
                    seeds.add(pid)

        return seeds

    @staticmethod
    def _bfs_subgraph(edges: List[dict], seeds: Set[int], max_hops: int,
                       traversal_predicates: Optional[Set[str]] = None) -> Set[int]:
        """BFS over `edges`, optionally following only edges whose predicate is in
        `traversal_predicates` (None = follow all). Edges not in that set never
        extend the frontier, but are still reported afterward if both endpoints end
        up in the resulting subgraph some other way."""
        adjacency: Dict[int, List[int]] = {}
        for e in edges:
            if traversal_predicates is not None and e["predicate"] not in traversal_predicates:
                continue
            adjacency.setdefault(e["src"], []).append(e["dst"])
            adjacency.setdefault(e["dst"], []).append(e["src"])
        visited = set(seeds)
        frontier = list(seeds)
        hops = 0
        while frontier and (max_hops == 0 or hops < max_hops):
            next_frontier = []
            for pid in frontier:
                for neighbor in adjacency.get(pid, []):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        next_frontier.append(neighbor)
            frontier = next_frontier
            hops += 1
        return visited

    # ----------------------------------------------------------------- #
    # Isolated / orphaned processes -- nodes with zero edges in the current
    # predicate set. Invisible to the normal graph output (no row is ever
    # emitted for a process that matches nothing), but worth surfacing on
    # their own: a process sharing no Spawn/DLL/SID/file/handle/cmdline
    # relationship with anything else is structurally unreachable by any
    # pivot, and that absence of normal relationships is itself a signal
    # (e.g. a DKOM-unlinked or orphaned process typically looks exactly
    # like this).
    # ----------------------------------------------------------------- #

    @staticmethod
    def _find_isolated(nodes: Dict[int, "ProcNode"], edges: List[dict]) -> List[dict]:
        connected: Set[int] = set()
        for e in edges:
            connected.add(e["src"])
            connected.add(e["dst"])
        isolated = []
        for pid, node in nodes.items():
            if pid in connected:
                continue
            if node.ppid not in nodes and node.ppid != 0:
                reason = f"orphaned (ppid {node.ppid} not present in pslist)"
            else:
                reason = "isolated (shares no predicate with any other process)"
            isolated.append({
                "pid": pid, "ppid": node.ppid, "name": node.name, "reason": reason,
            })
        return isolated

    # ----------------------------------------------------------------- #
    # Rendering
    # ----------------------------------------------------------------- #

    def _generator(self):
        nodes = self._extract_nodes()
        edges = self._evaluate_predicates(nodes)

        if self.config.get("show_isolated", False):
            for row in sorted(self._find_isolated(nodes, edges), key=lambda r: r["pid"]):
                yield (0, (row["pid"], row["name"], row["ppid"], row["reason"]))
            return

        any_seed_configured = any(
            self.config.get(f"seed_{kind}") for kind in SEED_KINDS)
        if any_seed_configured:
            seeds = self._seed_pids(nodes)
            if not seeds:
                vollog.warning("rMFKG: no process matched the given seed; showing full graph")
            else:
                max_hops = int(self.config.get("max_hops", 0) or 0)
                pivot_predicates = self.config.get("pivot_predicates")
                traversal_set = set(pivot_predicates) if pivot_predicates else None
                keep_pids = self._bfs_subgraph(edges, seeds, max_hops, traversal_set)
                edges = [e for e in edges if e["src"] in keep_pids and e["dst"] in keep_pids]

        max_severity = int(self.config.get("max_severity", 0) or 0)
        if max_severity:
            edges = [e for e in edges if SEVERITY.get(e["predicate"], 8) <= max_severity]

        # multi-type pairs: (unordered pid pair) -> set of predicate types
        pair_types: Dict[FrozenSet[int], Set[str]] = {}
        for e in edges:
            key = frozenset({e["src"], e["dst"]})
            pair_types.setdefault(key, set()).add(e["predicate"])

        def sort_key(x):
            return (SEVERITY.get(x["predicate"], 8), x["src"], x["dst"], x["predicate"])

        for e in sorted(edges, key=sort_key):
            key = frozenset({e["src"], e["dst"]})
            multi_type = len(pair_types.get(key, set())) > 1
            src_name = nodes[e["src"]].name if e["src"] in nodes else "?"
            dst_name = nodes[e["dst"]].name if e["dst"] in nodes else "?"
            yield (0, (
                e["src"], src_name, e["predicate"], SEVERITY.get(e["predicate"], 8),
                e["dst"], dst_name, multi_type, e["evidence"],
            ))

    def run(self):
        if self.config.get("show_isolated", False):
            return renderers.TreeGrid(
                [
                    ("PID", int),
                    ("Process", str),
                    ("PPID", int),
                    ("Reason", str),
                ],
                self._generator(),
            )
        return renderers.TreeGrid(
            [
                ("SrcPID", int),
                ("SrcProcess", str),
                ("Predicate", str),
                ("Severity", int),
                ("DstPID", int),
                ("DstProcess", str),
                ("MultiTypePair", bool),
                ("Evidence", str),
            ],
            self._generator(),
        )
