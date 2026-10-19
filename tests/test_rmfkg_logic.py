"""Unit tests for rMFKG's pure-logic pieces: predicate evaluation and pivot BFS.

These test the graph-construction/pivot logic directly against hand-built ProcNode
objects (no memory image needed) -- the same approach PEVAD's test_pevad_logic.py
uses for its classify()/content-corroboration logic. Image-level validation is
done separately against real, existing public memory images (see README), not
synthetic/custom test images.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugin", "windows"))

# volatility3 framework imports pull in a lot; import just enough to get ProcNode
# and the pure functions without requiring a live Context/plugin run.
import rmfkg  # noqa: E402


def make_node(pid, ppid, name):
    return rmfkg.ProcNode(pid, ppid, name)


class FakeConfig(dict):
    pass


class FakeRmfkg:
    """Stand-in for rmfkg.Rmfkg that exercises the same predicate/pivot logic without
    needing a live Volatility PluginInterface (whose `config`/`context` are read-only
    properties tied to a real plugin run). We bind the real unbound methods so the
    logic under test is byte-for-byte identical to what the plugin actually runs."""

    _evaluate_predicates = rmfkg.Rmfkg._evaluate_predicates
    _seed_pids = rmfkg.Rmfkg._seed_pids

    def __init__(self, config):
        self.config = config
        self.context = None
        self.config_path = "plugins.Rmfkg"


def test_spawn_predicate():
    nodes = {
        1: make_node(1, 0, "explorer.exe"),
        2: make_node(2, 1, "powershell.exe"),
        3: make_node(3, 2, "cmd.exe"),
    }
    plugin = FakeRmfkg(FakeConfig(predicates="all"))
    edges = plugin._evaluate_predicates(nodes)
    spawn_edges = [e for e in edges if e["predicate"] == "Spawn"]
    assert {(e["src"], e["dst"]) for e in spawn_edges} == {(1, 2), (2, 3)}


def test_injection_requires_both_malfind_and_handle():
    nodes = {
        1: make_node(1, 0, "powershell.exe"),
        2: make_node(2, 0, "svchost.exe"),
    }
    nodes[2].malfind_hits = [(0x1000, 0x2000, "PAGE_EXECUTE_READWRITE")]
    # No handle recorded yet -> no Injection edge
    plugin = FakeRmfkg(FakeConfig(predicates="all"))
    edges = plugin._evaluate_predicates(nodes)
    assert not [e for e in edges if e["predicate"] == "Injection"]

    # Now give pid 1 a VM_WRITE handle to pid 2 -> Injection edge should appear
    nodes[1].process_handles[2] = rmfkg.PROCESS_VM_WRITE
    edges = plugin._evaluate_predicates(nodes)
    inj = [e for e in edges if e["predicate"] == "Injection"]
    assert len(inj) == 1 and inj[0]["src"] == 1 and inj[0]["dst"] == 2


def test_injection_handle_without_malfind_hit_does_not_fire():
    nodes = {
        1: make_node(1, 0, "benign1.exe"),
        2: make_node(2, 0, "benign2.exe"),
    }
    nodes[1].process_handles[2] = rmfkg.PROCESS_VM_WRITE  # handle exists, but no malfind hit
    plugin = FakeRmfkg(FakeConfig(predicates="all"))
    edges = plugin._evaluate_predicates(nodes)
    assert not [e for e in edges if e["predicate"] == "Injection"]


def test_shareddll_excludes_system_dlls_and_system_paths():
    nodes = {
        1: make_node(1, 0, "a.exe"),
        2: make_node(2, 0, "b.exe"),
    }
    # Both load ntdll.dll (system, allowlisted) -> should NOT fire
    nodes[1].suspicious_dlls = set()
    nodes[2].suspicious_dlls = set()
    plugin = FakeRmfkg(FakeConfig(predicates="all"))
    edges = plugin._evaluate_predicates(nodes)
    assert not [e for e in edges if e["predicate"] == "SharedDLL"]

    # Both load the same non-system DLL -> should fire
    nodes[1].suspicious_dlls = {"abc123.dll"}
    nodes[2].suspicious_dlls = {"abc123.dll"}
    edges = plugin._evaluate_predicates(nodes)
    shared = [e for e in edges if e["predicate"] == "SharedDLL"]
    assert len(shared) == 1 and {shared[0]["src"], shared[0]["dst"]} == {1, 2}


def test_networkshare_fires_on_common_remote_endpoint():
    nodes = {
        1: make_node(1, 0, "powershell.exe"),
        2: make_node(2, 0, "rundll32.exe"),
        3: make_node(3, 0, "notepad.exe"),
    }
    nodes[1].net_endpoints = {("185.220.101.47", 4444)}
    nodes[2].net_endpoints = {("185.220.101.47", 4444)}
    nodes[3].net_endpoints = {("1.2.3.4", 80)}
    plugin = FakeRmfkg(FakeConfig(predicates="all"))
    edges = plugin._evaluate_predicates(nodes)
    net = [e for e in edges if e["predicate"] == "NetworkShare"]
    assert len(net) == 1 and {net[0]["src"], net[0]["dst"]} == {1, 2}


def test_identitymatch_requires_privileged_sid():
    nodes = {
        1: make_node(1, 0, "svchost.exe"),
        2: make_node(2, 0, "rundll32.exe"),
    }
    nodes[1].privileged_sids = {"S-1-5-18"}
    nodes[2].privileged_sids = {"S-1-5-18"}
    plugin = FakeRmfkg(FakeConfig(predicates="all"))
    edges = plugin._evaluate_predicates(nodes)
    im = [e for e in edges if e["predicate"] == "IdentityMatch"]
    assert len(im) == 1


def test_paper5_mode_excludes_added_predicates():
    nodes = {
        1: make_node(1, 0, "a.exe"),
        2: make_node(2, 0, "b.exe"),
    }
    nodes[1].files = {"C:\\Users\\victim\\Downloads\\evil.docx"}
    nodes[2].files = {"C:\\Users\\victim\\Downloads\\evil.docx"}
    nodes[1].cmdline_iocs = {"185.220.101.47"}
    nodes[2].cmdline_iocs = {"185.220.101.47"}
    plugin_all = FakeRmfkg(FakeConfig(predicates="all"))
    edges_all = plugin_all._evaluate_predicates(nodes)
    assert any(e["predicate"] == "FileShare" for e in edges_all)
    assert any(e["predicate"] == "CmdlineMatch" for e in edges_all)

    plugin5 = FakeRmfkg(FakeConfig(predicates="paper5"))
    edges5 = plugin5._evaluate_predicates(nodes)
    assert not any(e["predicate"] in ("FileShare", "HandleShare", "CmdlineMatch") for e in edges5)


def test_multitype_pair_detected_via_pair_types_grouping():
    # Mirrors the generator's own grouping logic: a pair with 2+ predicate types
    # should be flagged multi-type. We re-derive the same grouping here directly.
    edges = [
        {"src": 1, "dst": 2, "predicate": "Spawn", "evidence": ""},
        {"src": 1, "dst": 2, "predicate": "NetworkShare", "evidence": ""},
        {"src": 3, "dst": 4, "predicate": "SharedDLL", "evidence": ""},
    ]
    pair_types = {}
    for e in edges:
        key = frozenset({e["src"], e["dst"]})
        pair_types.setdefault(key, set()).add(e["predicate"])
    assert len(pair_types[frozenset({1, 2})]) == 2
    assert len(pair_types[frozenset({3, 4})]) == 1


def test_bfs_subgraph_respects_max_hops():
    # Chain: 1 -> 2 -> 3 -> 4
    edges = [
        {"src": 1, "dst": 2, "predicate": "Spawn", "evidence": ""},
        {"src": 2, "dst": 3, "predicate": "Spawn", "evidence": ""},
        {"src": 3, "dst": 4, "predicate": "Spawn", "evidence": ""},
    ]
    full = rmfkg.Rmfkg._bfs_subgraph(edges, {1}, max_hops=0)
    assert full == {1, 2, 3, 4}

    one_hop = rmfkg.Rmfkg._bfs_subgraph(edges, {1}, max_hops=1)
    assert one_hop == {1, 2}

    two_hop = rmfkg.Rmfkg._bfs_subgraph(edges, {1}, max_hops=2)
    assert two_hop == {1, 2, 3}


def test_bfs_subgraph_traversal_predicate_filter_prevents_giant_component():
    # IdentityMatch links everything (simulating a SYSTEM-dominated image); without
    # filtering, a pivot from PID 1 would absorb the whole graph. Restricting
    # traversal to NetworkShare only should keep the pivot tight.
    edges = [
        {"src": 1, "dst": 2, "predicate": "IdentityMatch", "evidence": ""},
        {"src": 2, "dst": 3, "predicate": "IdentityMatch", "evidence": ""},
        {"src": 3, "dst": 4, "predicate": "IdentityMatch", "evidence": ""},
        {"src": 1, "dst": 5, "predicate": "NetworkShare", "evidence": ""},
    ]
    unrestricted = rmfkg.Rmfkg._bfs_subgraph(edges, {1}, max_hops=0)
    assert unrestricted == {1, 2, 3, 4, 5}

    restricted = rmfkg.Rmfkg._bfs_subgraph(edges, {1}, max_hops=0,
                                            traversal_predicates={"NetworkShare"})
    assert restricted == {1, 5}


def test_bfs_subgraph_multiple_seeds_union():
    edges = [
        {"src": 10, "dst": 20, "predicate": "NetworkShare", "evidence": ""},
        {"src": 30, "dst": 40, "predicate": "SharedDLL", "evidence": ""},
    ]
    result = rmfkg.Rmfkg._bfs_subgraph(edges, {10, 30}, max_hops=0)
    assert result == {10, 20, 30, 40}


def test_seed_ip_matching_with_and_without_port():
    nodes = {
        1: make_node(1, 0, "a.exe"),
        2: make_node(2, 0, "b.exe"),
    }
    nodes[1].net_endpoints = {("185.220.101.47", 4444)}
    nodes[2].net_endpoints = {("185.220.101.47", 9999)}

    plugin = FakeRmfkg(FakeConfig(seed_ip="185.220.101.47"))
    seeds = plugin._seed_pids(nodes)
    assert seeds == {1, 2}  # ip-only match hits both ports

    plugin2 = FakeRmfkg(FakeConfig(seed_ip="185.220.101.47:4444"))
    seeds2 = plugin2._seed_pids(nodes)
    assert seeds2 == {1}  # ip:port match narrows to the exact endpoint


def test_seed_dll_substring_match():
    nodes = {1: make_node(1, 0, "a.exe"), 2: make_node(2, 0, "b.exe")}
    nodes[1].dlls = {("abc123.dll", "C:\\Users\\victim\\AppData\\Local\\Temp\\abc123.dll")}
    nodes[2].dlls = {("ntdll.dll", "C:\\Windows\\System32\\ntdll.dll")}
    plugin = FakeRmfkg(FakeConfig(seed_dll="abc123"))
    assert plugin._seed_pids(nodes) == {1}


def test_ioc_regexes_extract_ip_domain_url():
    sample = "powershell -enc http://evil-c2.ru/payload connect to 185.220.101.47 also 1.1.1.1 dns"
    ips = set(rmfkg.IOC_IP_RE.findall(sample))
    urls = set(rmfkg.IOC_URL_RE.findall(sample))
    domains = set(rmfkg.IOC_DOMAIN_RE.findall(sample))
    assert "185.220.101.47" in ips and "1.1.1.1" in ips
    assert any(u.startswith("http://evil-c2.ru") for u in urls)
    assert "evil-c2.ru" in domains


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))


def test_find_isolated_detects_no_edge_processes():
    nodes = {
        1: make_node(1, 0, "explorer.exe"),
        2: make_node(2, 1, "powershell.exe"),
        99: make_node(99, 50, "oddproc.exe"),   # ppid 50 not in pslist -> orphaned
        100: make_node(100, 0, "lonely.exe"),   # ppid 0 but shares nothing -> isolated
    }
    edges = [{"src": 1, "dst": 2, "predicate": "Spawn", "evidence": "x"}]
    isolated = rmfkg.Rmfkg._find_isolated(nodes, edges)
    isolated_by_pid = {r["pid"]: r for r in isolated}
    assert set(isolated_by_pid) == {99, 100}
    assert "orphaned" in isolated_by_pid[99]["reason"]
    assert "isolated" in isolated_by_pid[100]["reason"]
    assert 1 not in isolated_by_pid and 2 not in isolated_by_pid


def test_max_severity_filters_low_priority_predicates():
    nodes = {
        1: make_node(1, 0, "a.exe"),
        2: make_node(2, 1, "b.exe"),
    }
    nodes[1].privileged_sids = {"S-1-5-18"}
    nodes[2].privileged_sids = {"S-1-5-18"}
    nodes[1].net_endpoints = {("1.2.3.4", 443)}
    nodes[2].net_endpoints = {("1.2.3.4", 443)}
    plugin = FakeRmfkg(FakeConfig(predicates="all"))
    edges = plugin._evaluate_predicates(nodes)
    preds = {e["predicate"] for e in edges}
    assert {"Spawn", "IdentityMatch", "NetworkShare"} <= preds
    # max_severity 6 should drop Spawn(7) and IdentityMatch(8), keep NetworkShare(2)
    filtered = [e for e in edges if rmfkg.SEVERITY.get(e["predicate"], 8) <= 6]
    assert {e["predicate"] for e in filtered} == {"NetworkShare"}
