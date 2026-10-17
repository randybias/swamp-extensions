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
        if a[:3] == ["-j", "addr", "show"]:
            def info(ip, fam, scope): return [{"family": fam, "local": ip, "prefixlen": 24, "scope": scope}]
            if flag("no_addr"): print("[]"); return 0
            if flag("other_addr"): ai = info("203.0.113.9", "inet", "global")
            elif flag("ll_only"): ai = info("2001:db8::1", "inet6", "link")
            else: ai = info("192.0.2.10", "inet", "global")
            print(json.dumps([{"ifname": a[4], "addr_info": ai}])); return 0
        if s in ("-j route show default", "-j -4 route show default", "-j -6 route show default"):
            if flag("no_route"): print("[]"); return 0
            dev = "enp9s0" if flag("route_other_dev") else "enp1s0"
            print(json.dumps([{"dst": "default", "gateway": "192.0.2.1", "dev": dev}])); return 0
        if a[:3] == ["-j", "route", "get"]: print(json.dumps([{"dev":"enp1s0"}])); return 0
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
