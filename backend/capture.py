"""Opt-in metadata-only capture. Headers are parsed in place; packet bytes and payloads are never retained."""
import collections
import ctypes
import logging
import threading
import time

from . import pcap

class Capture:
    def __init__(self):
        self.lib=None; self.handles=[]; self.threads=[]; self.error=None; self.lock=threading.Lock()
        self.owners={}; self.bindings={}; self.totals=collections.defaultdict(lambda:[0,0])
        self.flows={}; self.domains={}; self.hellos={}; self.packets=0; self.attributed=0; self.server_names=0
        self.enabled=False; self.running=threading.Event()

    def update_owners(self, connections):
        owners=collections.defaultdict(set); bindings=collections.defaultdict(set)
        for c in connections:
            if not c.get("pid"):
                continue
            key=(c["protocol"],c["local_ip"],c["local_port"])
            bindings[key].add(c["app_id"])
            if c.get("remote_ip"):
                owners[key+(c["remote_ip"],c["remote_port"])].add(c["app_id"])
        with self.lock:
            self.owners=dict(owners); self.bindings=dict(bindings)

    def owner(self, protocol, local, lp, remote, rp):
        exact=self.owners.get((protocol,local,lp,remote,rp),set())
        if len(exact)==1:
            return next(iter(exact))
        if protocol=="UDP":
            candidates=set()
            for addr in (local,"0.0.0.0","::"):
                candidates.update(self.bindings.get((protocol,addr,lp),set()))
            if len(candidates)==1:
                return next(iter(candidates))
        return None

    def server_name(self, flow, payload, now):
        """TLS server name (SNI) from a ClientHello, reassembling a hello split across two segments."""
        pending=self.hellos.pop(flow,None)
        if pending:
            payload=pending[0]+payload
        hello=pcap.client_hello(payload)
        if not hello:
            return None
        needed,name=hello
        if name is None and needed>len(payload) and len(payload)<16384:
            if len(self.hellos)>256:
                self.hellos={k:v for k,v in self.hellos.items() if now-v[1]<5}
            self.hellos[flow]=(payload,now)
        return name

    def handle(self, dlt, data, full=None):
        """Account one captured frame. data may be a header-only prefix; full() returns the whole frame and is
        called only for DNS responses and TLS handshakes."""
        parsed=pcap.parse(dlt,data)
        if not parsed:
            return
        proto,src,sport,dst,dport,size,l4=parsed
        now=time.time(); answers=(); sni=None
        if proto=="UDP" and sport==pcap.DNS_PORT:
            answers=pcap.dns_answers(full() if full else data,l4)
        elif proto=="TCP":
            start=pcap.tcp_payload(data,l4); flow=(src,sport,dst,dport)
            if start is not None and start<len(data) and (data[start]==0x16 or flow in self.hellos):
                frame=full() if full else data
                sni=self.server_name(flow,frame[start:],now)
        with self.lock:
            self.packets+=1
            outbound=self.owner(proto,src,sport,dst,dport)
            inbound=self.owner(proto,dst,dport,src,sport)
            if not (outbound and inbound):  # local traffic can appear on multiple capture interfaces
                app_id=outbound or inbound
                if app_id:
                    self.attributed+=1
                    self.totals[app_id][0 if outbound else 1]+=size
                    lip,lp,rip,rp=(src,sport,dst,dport) if outbound else (dst,dport,src,sport)
                    self.flows[(app_id,proto,lip,lp,rip,rp)]=now
            for ip,name,ttl in answers:
                self.domains[ip]=(name,now+min(max(int(ttl),60),3600))
            if sni:
                self.domains[dst]=(sni,now+3600); self.server_names+=1
            if len(self.flows)>10000:
                self.flows={k:v for k,v in self.flows.items() if now-v<10}
            if len(self.domains)>4096:
                self.domains={k:v for k,v in self.domains.items() if v[1]>now}
                if len(self.domains)>4096:
                    self.domains.clear()

    def reader(self, handle):
        header=ctypes.POINTER(pcap.PacketHeader)(); data=ctypes.POINTER(ctypes.c_ubyte)()
        dlt=self.lib.pcap_datalink(handle)
        while self.running.is_set():
            result=self.lib.pcap_next_ex(handle,ctypes.byref(header),ctypes.byref(data))  # releases the GIL while waiting
            if result==1:
                caplen=header.contents.caplen
                # Copy only the headers; the rest of the frame is read only for DNS and TLS handshakes.
                self.handle(dlt,ctypes.string_at(data,min(caplen,128)),lambda: ctypes.string_at(data,caplen))
            elif result<0:
                if self.running.is_set():
                    self.error=(self.lib.pcap_geterr(handle) or b"Capture stopped").decode(errors="replace")[:300]
                return

    def start(self):
        if self.enabled:
            return
        self.enabled=True; self.error=None
        try:
            self.lib=self.lib or pcap.load()
            names=pcap.interfaces(self.lib)
            if not names:
                raise RuntimeError("No capturable network interfaces. Packet capture may require additional permissions.")
            failures=[]
            for name in names:
                try:
                    self.handles.append(pcap.open_live(self.lib,name))
                except RuntimeError as exc:
                    failures.append(str(exc))
            if not self.handles:
                raise RuntimeError("Capture permission denied or unavailable: "+(failures[0] if failures else "unknown error"))
            self.running.set()
            self.threads=[threading.Thread(target=self.reader,args=(h,),name="beaver-capture",daemon=True) for h in self.handles]
            for thread in self.threads:
                thread.start()
        except Exception as exc:
            self.error=str(exc)[:300]; self.close_handles()
            logging.getLogger("beaver").warning("Capture unavailable: %s",exc)

    def status(self):
        active=self.running.is_set() and any(t.is_alive() for t in self.threads)
        return {"enabled":self.enabled,"active":active,"error":self.error,"packets":self.packets,"interfaces":len(self.handles),
                "attributed":self.attributed,"server_names":self.server_names,
                "method":"IP-layer captured bytes; observed tuple ownership only"}

    def snapshot(self):
        now=time.time()
        with self.lock:
            return dict((k,list(v)) for k,v in self.totals.items()), {k:v for k,v in self.flows.items() if now-v<8}, {k:v[0] for k,v in self.domains.items() if v[1]>now}

    def close_handles(self):
        self.running.clear()
        for handle in self.handles:
            try:
                self.lib.pcap_breakloop(handle)
            except Exception:
                pass
        for thread in self.threads:
            thread.join(timeout=2)
        for handle in self.handles:
            try:
                self.lib.pcap_close(handle)
            except Exception:
                pass
        self.handles=[]; self.threads=[]

    def stop(self):
        self.close_handles(); self.enabled=False
