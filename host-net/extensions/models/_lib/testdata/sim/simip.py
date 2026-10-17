import json, os, sys, re, glob
R = os.environ["SIMROOT"]; F = R + "/state/links.json"
def load(): return json.load(open(F))
def save(l): json.dump(l, open(F, "w"))
def flag(n): return os.path.exists(R + "/state/" + n)
def log(m): open(R + "/state/log", "a").write(m + "\n")
def ensure(l, name, kind, mtu=1500):
    if not any(x["ifname"] == name for x in l):
        l.append({"ifname": name, "mtu": mtu, "operstate": "UP", "address": "02:00:00:00:01:%02x" % (len(l)+1), "linkinfo": {"info_kind": kind, "info_data": {"id": int(name.split(".")[1])} if kind == "vlan" else {}}})
def setmtu(l, name, mtu):
    for x in l:
        if x["ifname"] == name: x["mtu"] = mtu
def main():
    tool = sys.argv[1]; a = sys.argv[2:]
    l = load()
    if tool == "ip":
        s = " ".join(a)
        if s == "-d -j link": print(json.dumps(l)); return 0
        if s == "-j addr": print(json.dumps([{"ifname":"enp1s0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24}]}])); return 0
        v6 = flag("v6only") and not flag("lost_v6")
        def devaddr():
            if v6: return ("2001:db8::10", "inet6", "global", 64)
            if flag("other_addr"): return ("203.0.113.9", "inet", "global", 24)
            if flag("ll_only"): return ("2001:db8::1", "inet6", "link", 24)
            return ("192.0.2.20", "inet", "global", 25 if flag("prefix_changed") else 24)
        def path():
            if v6: return {"dev": "enp1s0", "gateway": "2001:db8::1", "flags": []}
            p = {"dev": "enp1s0", "gateway": "192.0.2.1", "flags": []}
            if flag("nondefault"): del p["gateway"]
            if flag("route_other_dev"): p["dev"] = "enp9s0"
            if flag("gw_changed"): p["gateway"] = "192.0.2.254"
            if flag("linkdown"): p["flags"] = ["linkdown"]
            return p
        if a[:3] == ["-j", "addr", "show"]:
            if flag("no_addr"): print("[]"); return 0
            ip, fam, scope, pl = devaddr()
            print(json.dumps([{"ifname": a[4], "addr_info": [{"family": fam, "local": ip, "prefixlen": pl, "scope": scope}]}])); return 0
        if a[:3] == ["-j", "route", "get"]:
            if flag("no_route"): print("[]"); return 0
            fr = R + "/state/flaky_route"
            if os.path.exists(fr):
                # The link is still re-settling: the first N lookups find nothing.
                n = int(open(fr).read().strip() or "0")
                if n > 0:
                    open(fr, "w").write(str(n - 1)); print("[]"); return 0
            out = {"dst": a[3], **path()}
            if "from" in a:
                # Like the kernel: with a source given there is no prefsrc, and
                # any locally configured source is accepted, whatever device it
                # is on; a loopback source routes through lo.
                frm = a[a.index("from") + 1]
                if flag("no_addr"):
                    print("RTNETLINK answers: Invalid argument", file=sys.stderr); return 2
                out["from"] = frm
                if frm.startswith("127.") or frm == "::1":
                    out["dev"] = "lo"
            else:
                out["prefsrc"] = devaddr()[0]
            print(json.dumps([out])); return 0
        if s in ("-j route show default", "-j -4 route show default", "-j -6 route show default"):
            print("[]" if flag("no_route") else json.dumps([{"dst": "default", "gateway": "192.0.2.1", "dev": "enp1s0"}])); return 0
        if a[:3] == ["link", "show", "dev"]:
            return 0 if any(x["ifname"] == a[3] for x in l) else 1
        if a[:3] == ["link", "delete", "dev"]:
            n = a[3]
            if not any(x["ifname"] == n for x in l): return 1
            save([x for x in l if x["ifname"] != n]); log("ip delete " + n); return 0
        if a[:3] == ["link", "set", "dev"] and "mtu" in a:
            if os.environ.get("SIM_FAIL_MTU"): return 2
            setmtu(l, a[3], int(a[a.index("mtu")+1])); save(l); log("ip mtu %s %s" % (a[3], a[a.index("mtu")+1])); return 0
        print("ip stub: unhandled " + s, file=sys.stderr); return 9
    if tool == "netplan":
        if a and a[0] == "generate": return 0
        if a == ["apply"]:
            log("netplan apply")
            if flag("apply_kills_session"):
                # The management NIC bounces and the SSH session dies: whatever
                # the session started is hung up (SIGHUP), like sshd does.
                try:
                    sp = int(os.environ["SIM_SESSION_PID"])
                    for d in os.listdir("/proc"):
                        if d.isdigit():
                            try:
                                ppid = int(open("/proc/%s/stat" % d).read().rsplit(")", 1)[1].split()[1])
                            except Exception: continue
                            if ppid == sp: os.kill(int(d), 1)
                except Exception: pass
            for f in sorted(glob.glob(R + "/etc/netplan/*.yaml")):
                txt = open(f).read()
                for m in re.finditer(r'^    "([^"]+)":\n((?:      .*\n)*)', txt, re.M):
                    name, body = m.group(1), m.group(2)
                    mtu = re.search(r"mtu: (\d+)", body)
                    if "id:" in body: ensure(l, name, "vlan")
                    if mtu: setmtu(l, name, int(mtu.group(1)))
            save(l)
            if flag("apply_fails"): print("Cannot find unique matching interface for enp1s0", file=sys.stderr); return 1
            return 0
    if tool == "networkctl":
        log("networkctl " + " ".join(a))
        for f in glob.glob(R + "/etc/systemd/network/*.netdev"):
            m = re.search(r"Name=(\S+)", open(f).read())
            if m: ensure(l, m.group(1), "vlan" if "." in m.group(1) else "bridge")
        for f in glob.glob(R + "/etc/systemd/network/*.network"):
            t = open(f).read(); n = re.search(r"Name=(\S+)", t); mt = re.search(r"MTUBytes=(\d+)", t)
            if n and mt: setmtu(l, n.group(1), int(mt.group(1)))
        save(l); return 0
    return 0
sys.exit(main())
