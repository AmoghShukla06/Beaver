"""Optional real capture diagnostic against an official HTTPS website. No payload retained."""
import json
import socket
import ssl
import tempfile
import time
from backend.storage import Store
from backend.monitor import Monitor

with tempfile.TemporaryDirectory(prefix="beaver-capture-") as directory:
    store=Store(directory);store.set_settings({"capture":True});monitor=Monitor(store)
    conn=None
    try:
        monitor.sample();time.sleep(2)
        if not monitor.capture.status()["active"]:
            print(json.dumps({"capture":monitor.capture.status(),"verified":False}))
        else:
            conn=ssl.create_default_context().wrap_socket(socket.create_connection(("www.python.org",443),timeout=10),server_hostname="www.python.org")
            monitor.sample()
            conn.sendall(b"GET / HTTP/1.1\r\nHost: www.python.org\r\nConnection: close\r\n\r\n")
            received=0
            while True:
                chunk=conn.recv(65536)
                if not chunk:break
                received+=len(chunk)
            time.sleep(2);monitor.sample()
            snapshot=monitor.snapshot()
            import os
            own=next(a for a in snapshot["apps"] if os.getpid() in a["pids"])
            result={"capture":snapshot["coverage"]["capture"],"application_uploaded":own["uploaded"],"application_downloaded":own["downloaded"],"received_bytes":received,"verified":own["downloaded"]>0 and own["uploaded"]>0}
            print(json.dumps(result))
            if not result["verified"]:raise SystemExit(1)
    finally:
        if conn:conn.close()
        monitor.stop();store.close()
