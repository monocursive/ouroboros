import json, glob
for f in sorted(glob.glob("/tmp/bench-results/*.json")):
    d = json.load(open(f))
    print("##", f.split("/")[-1].replace(".json", ""))
    base = d["results"][0]["mean"]
    for b in d["results"]:
        cmd = b["command"].split(" ")[0][:24]
        print(f"  {cmd:<26} mean={b['mean']*1000:9.1f}ms  min={b['min']*1000:9.1f}ms  max={b['max']*1000:9.1f}ms  overhead={b['mean']/base:7.1f}x")
