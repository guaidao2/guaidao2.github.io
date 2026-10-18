#!/usr/bin/env python3
"""traffic.pcapng solver: reassemble the flag from base64 pixel-beacon fragments.

Each data-bearing request looks like
  GET /pixel.gif?d=<base64>&s=<HH>&r=<random>
so: pull every http.request.full_uri, keep those with d= and s=, URL-decode d,
base64-decode it, sort by s, concatenate.
"""
import base64, re, subprocess, sys, urllib.parse

pcap = sys.argv[1] if len(sys.argv) > 1 else "traffic.pcapng"
out = subprocess.run(["tshark", "-r", pcap, "-Y", "http.request",
                      "-T", "fields", "-e", "frame.number",
                      "-e", "http.request.full_uri"],
                     capture_output=True, text=True).stdout

frags = {}
for line in out.splitlines():
    if not line.strip():
        continue
    num, _, uri = line.partition("\t")
    m = re.search(r"[?&]d=([^&]+)", uri)
    s = re.search(r"[?&]s=(\d+)", uri)
    if not (m and s):
        continue
    b = base64.b64decode(urllib.parse.unquote(m.group(1)))
    frags[s.group(1)] = b
    print("frame %-4s s=%s  %r" % (num, s.group(1), b))

flag = b"".join(frags[k] for k in sorted(frags))
print("FLAG:", flag.decode())
