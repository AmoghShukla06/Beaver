"""Private line-delimited JSON RPC over inherited stdin/stdout. No listening socket."""
import argparse
import json
import logging
import logging.handlers
import os
import platform
from pathlib import Path
import sys
import threading

import psutil

from .firewall import Firewall, rule_id, validate
from .monitor import Monitor
from .storage import Store

SLOW={"refresh_feed","download_geoip","block","unblock","verify_rules"}

class Service:
    def __init__(self,directory,output=None):
        self.output=output; self.write_lock=threading.Lock()
        self.store=Store(directory); self.monitor=Monitor(self.store,self.emit); self.firewall=Firewall(self.store)

    def emit(self,event,data):
        """Unsolicited event line (no id). Lets the desktop react to alerts without polling."""
        if self.output:
            self.send({"event":event,"data":data})

    def send(self,message):
        with self.write_lock:
            self.output.write(json.dumps(message,allow_nan=False)+"\n"); self.output.flush()

    def handle(self,request):
        try:
            response={"id":request.get("id"),"result":self.dispatch(request["method"],request.get("params",{}))}
        except Exception as exc:
            response={"id":request.get("id"),"error":str(exc)[:600]}
            if not isinstance(exc,(ValueError,KeyError)):  # validation errors are user-facing, not faults
                logging.getLogger("beaver").exception("RPC %s failed",request.get("method"))
        self.send(response)

    def dispatch(self,method,params):
        if not isinstance(params,dict):
            raise ValueError("Expected an object")
        if method=="snapshot":
            return self.monitor.snapshot() | {"alerts":self.store.alerts(),"rules":self.firewall.rules(),
                "settings":self.store.settings(),"allowlist":self.store.allowlist(),"firewall":self.firewall.capabilities(),"data_path":str(self.store.directory)}
        if method=="history":
            return self.store.history(str(params["app_id"]),params.get("offset",0),params.get("limit",50))
        if method=="settings":
            patch=params.get("patch",{})
            if not isinstance(patch,dict):
                raise ValueError("Invalid settings")
            if patch.get("geoip_path"):
                import maxminddb
                with maxminddb.open_database(patch["geoip_path"]) as reader:
                    if "City" not in reader.metadata().database_type:
                        raise ValueError("Choose a MaxMind-compatible City database with coordinates")
            return self.store.set_settings(patch)
        if method=="download_geoip":
            from .geodownload import download_city
            path=download_city(self.store.directory)
            return self.store.set_settings({"geoip_path":path})
        if method=="refresh_feed":
            return self.monitor.intel.refresh()
        if method=="acknowledge":
            self.store.acknowledge(str(params["id"])); self.monitor.summary=None; return {"ok":True}
        if method=="visibility":
            self.monitor.set_visible(params.get("visible") is True); return {"ok":True}
        if method=="terminate":
            return self.monitor.terminate(str(params["app_id"]))
        if method=="verify_rules":
            return self.firewall.verify()
        if method=="block":
            return self.firewall.apply(params["kind"],params["target"])
        if method=="unblock":
            return self.firewall.remove(str(params["id"]))
        if method=="allowlist":
            kind=params["kind"]; target=params["target"]; enabled=params["enabled"]
            if type(enabled) is not bool or kind not in ("application","endpoint"):
                raise ValueError("Invalid allowlist entry")
            if kind=="endpoint":
                target=validate(kind,target)
            elif not isinstance(target,str) or not Path(target).is_absolute() or len(target)>4096:
                raise ValueError("Expected absolute application path")
            entry={"id":rule_id(kind,target),"kind":kind,"target":target}
            self.store.allow(entry,enabled); return {"ok":True}
        raise ValueError("Unknown method")

def background_priority():
    """A permanent background monitor should never compete with foreground work."""
    try:
        psutil.Process().nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if os.name=="nt" else 10)
    except (psutil.Error,OSError,AttributeError):
        pass

def setup_logging(directory):
    """Local rotating log (about 3 MB max). Errors only; never connection data."""
    folder=Path(directory)/"logs"; folder.mkdir(parents=True,exist_ok=True)
    handler=logging.handlers.RotatingFileHandler(folder/"service.log",maxBytes=1_000_000,backupCount=2,encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger=logging.getLogger("beaver"); logger.addHandler(handler); logger.setLevel(logging.INFO)
    logger.info("Service started on %s %s (Python %s)",platform.system(),platform.release(),platform.python_version())

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--data-dir",required=True); args=parser.parse_args()
    setup_logging(args.data_dir)
    background_priority()
    service=Service(args.data_dir,sys.stdout); service.monitor.start()
    threading.Thread(target=service.firewall.verify_quietly,daemon=True).start()
    try:
        for line in sys.stdin:
            request={}
            try:
                if len(line)>65536:
                    raise ValueError("Request is too large")
                request=json.loads(line)
                if not isinstance(request,dict):
                    raise ValueError("Expected an object")
            except Exception as exc:
                service.send({"id":None,"error":str(exc)[:600]}); continue
            if request.get("method") in SLOW:
                # Network downloads and OS authorization prompts must not stall live snapshots.
                threading.Thread(target=service.handle,args=(request,),daemon=True).start()
            else:
                service.handle(request)
    finally:
        service.monitor.stop(); service.store.close()

if __name__=="__main__":
    main()
