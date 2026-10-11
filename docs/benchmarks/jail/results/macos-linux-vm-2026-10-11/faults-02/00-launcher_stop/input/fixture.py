import os, time
for i in range(6):
    if os.fork() == 0:
        os.setsid()
        print("DETACHED", os.getpid(), flush=True)
        while True:
            time.sleep(.1)
print("READY", flush=True)
while True:
    print("TICK", time.monotonic_ns(), flush=True)
    time.sleep(.1)
