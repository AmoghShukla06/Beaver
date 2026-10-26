"""User-requested native firewall operations, narrowly scoped to Beaver-owned rules."""
import base64
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

class FirewallError(RuntimeError):
    pass

def rule_id(kind,target):
    return hashlib.sha256((kind+":"+target).encode()).hexdigest()[:24]

def validate(kind,target,system=None):
    system=system or platform.system()
    if not isinstance(target,str) or len(target)>4096 or any(ord(c)<32 for c in target):
        raise ValueError("Invalid firewall target")
    if kind=="endpoint":
        addr=ipaddress.ip_address(target)
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
            raise ValueError("Loopback, unspecified and multicast addresses cannot be blocked")
        return str(addr)
    if kind=="application":
        if system!="Windows":
            raise ValueError("Linux does not support executable-path rules in nftables. Block selected remote endpoints instead.")
        if not Path(target).is_absolute() or not Path(target).is_file():
            raise ValueError("Select an existing absolute executable path")
        return str(Path(target).resolve())
    if kind=="ports":
        try:
            ports=sorted({int(p) for p in target.split(",")})
        except ValueError:
            raise ValueError("Ports must be numbers separated by commas") from None
        if not ports or len(ports)>32 or not all(1<=p<=65535 for p in ports):
            raise ValueError("Choose 1-32 ports between 1 and 65535")
        return ",".join(map(str,ports))
    raise ValueError("Unsupported rule type")

# Inbound remote-login services blocked by Remote access lockdown. SSH is omitted: blocking it can lock out servers.
LOCKDOWN_PORTS="23,3389,5900,5901,5902,5903,5938,5985,5986"

def ps_literal(value):
    return "'"+value.replace("'","''")+"'"

def windows_script(kind,target,remove=False):
    identifier="Beaver-"+rule_id(kind,target)
    names=[identifier+"-In",identifier+"-Out"]
    cleanup=";".join("Get-NetFirewallRule -Name "+ps_literal(n)+" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop" for n in names)
    if remove:
        return "$ErrorActionPreference='Stop';"+cleanup
    if kind=="ports":  # validated digits and commas only; inbound TCP only
        option="-Protocol TCP -LocalPort "+target+" "; directions=["Inbound"]
    else:
        option=("-Program " if kind=="application" else "-RemoteAddress ")+ps_literal(target)+" "; directions=["Inbound","Outbound"]
    adds=";".join("New-NetFirewallRule -Name "+ps_literal(n)+" -DisplayName "+ps_literal(n)+" -Group 'Beaver' -Direction "+direction+" -Action Block -Profile Any "+option+"-ErrorAction Stop | Out-Null" for n,direction in zip(names,directions))
    return "$ErrorActionPreference='Stop';try {"+cleanup+";"+adds+"} catch {"+cleanup+";exit 1}"

def linux_script(kind,target,remove=False):
    if kind not in ("endpoint","ports"):
        raise ValueError("Linux supports endpoint and port rules only")
    table="beaver_"+rule_id(kind,target)
    if remove:
        return f"delete table inet {table}\n"
    if kind=="ports":
        ports=validate("ports",target,"Linux")
        return (f"add table inet {table}\n"
            f"add chain inet {table} input {{ type filter hook input priority -10; policy accept; }}\n"
            f"add rule inet {table} input iifname != \"lo\" tcp dport {{ {ports.replace(',',', ')} }} drop\n")
    addr=ipaddress.ip_address(target)
    family="ip6" if addr.version==6 else "ip"
    return (f"add table inet {table}\n"
        f"add chain inet {table} output {{ type filter hook output priority -10; policy accept; }}\n"
        f"add chain inet {table} input {{ type filter hook input priority -10; policy accept; }}\n"
        f"add rule inet {table} output {family} daddr {addr} drop\n"
        f"add rule inet {table} input {family} saddr {addr} drop\n")

class Firewall:
    def __init__(self,store,runner=subprocess.run,boot_time=None):
        self.store=store; self.runner=runner; self.system=platform.system()
        import psutil
        self.boot_time=boot_time or psutil.boot_time

    def capabilities(self):
        return {"platform":self.system,"endpoint":self.system=="Windows" or (self.system=="Linux" and bool(shutil.which("nft"))),
                "application":self.system=="Windows","ports":self.system=="Windows" or (self.system=="Linux" and bool(shutil.which("nft"))),
                "lockdown":LOCKDOWN_PORTS,"elevation":"Windows UAC" if self.system=="Windows" else "polkit (pkexec)",
                "note":"Rules require approval in the operating system. Endpoint blocks affect every application. Linux executable-path blocking is unavailable."}

    def execute(self,kind,target,remove):
        if self.system=="Windows":
            script=windows_script(kind,target,remove)
            encoded=base64.b64encode(script.encode("utf-16-le")).decode("ascii")
            wrapper="$p=Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',"+ps_literal(encoded)+");exit $p.ExitCode"
            result=self.runner(["powershell.exe","-NoProfile","-NonInteractive","-Command",wrapper],capture_output=True,text=True,timeout=120,creationflags=0x08000000)
        elif self.system=="Linux":
            nft=shutil.which("nft")
            if not nft:
                raise FirewallError("Install nftables to manage endpoint blocks")
            cmd=[nft,"-f","-"]
            if os.geteuid()!=0:
                if not shutil.which("pkexec"):
                    raise FirewallError("Install polkit (pkexec) for per-action authorization")
                cmd=["pkexec"]+cmd
            result=self.runner(cmd,input=linux_script(kind,target,remove),capture_output=True,text=True,timeout=120)
        else:
            raise FirewallError("Unsupported operating system")
        if result.returncode:
            raise FirewallError("The operating system did not apply the rule. Authorization may have been cancelled. "+str(result.stderr or "")[-500:])

    def rules(self):
        """Recorded rules with live state. nftables rules added at runtime do not survive a reboot."""
        rules=self.store.rules()
        if self.system=="Linux":
            booted=self.boot_time()
            rules=[r|{"state":"inactive"} if r["state"]=="applied" and (r.get("verified_at") or 0)<booted else r for r in rules]
        return rules

    def present(self):
        """Names of Beaver rules currently in the OS firewall, or None when they cannot be read unprivileged."""
        if self.system=="Windows":
            script="@(Get-NetFirewallRule -Group 'Beaver' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) | ConvertTo-Json -Compress"
            result=self.runner(["powershell.exe","-NoProfile","-NonInteractive","-Command",script],capture_output=True,text=True,timeout=60,creationflags=0x08000000)
            if result.returncode:
                return None
            names=json.loads(result.stdout or "[]")
            return {names} if isinstance(names,str) else set(names or [])
        if self.system=="Linux" and os.geteuid()==0 and shutil.which("nft"):
            result=self.runner([shutil.which("nft"),"list","tables"],capture_output=True,text=True,timeout=30)
            return None if result.returncode else {line.split()[-1] for line in result.stdout.splitlines() if line.strip()}
        return None

    def verify(self):
        """Reconcile recorded rules with the OS. Read-only: never re-applies or removes anything."""
        present=self.present(); now=time.time()
        if present is None:
            return {"verified":False,"rules":self.store.rules(),"note":"Rule state cannot be read without elevation on this system."}
        for rule in self.store.rules():
            if rule["state"] not in ("applied","missing"):
                continue
            ident=("Beaver-"+rule["id"]+"-In") if self.system=="Windows" else ("beaver_"+rule["id"])
            self.store.put_rule(rule|({"state":"applied","verified_at":now} if ident in present else {"state":"missing"}))
        return {"verified":True,"rules":self.store.rules()}

    def verify_quietly(self):
        try:
            if self.store.rules():
                self.verify()
        except Exception:
            pass

    def apply(self,kind,target):
        target=validate(kind,target,self.system); rid=rule_id(kind,target)
        existing=next((r for r in self.rules() if r["id"]==rid),None)
        if existing and existing["state"]=="applied":
            return existing
        pending={"id":rid,"kind":kind,"target":target,"created":time.time(),"state":"pending","verified_at":None}
        self.store.put_rule(pending)  # Journal before OS mutation; crash leaves an explicitly unverified rule.
        try:
            self.execute(kind,target,False)
        except Exception:
            self.store.put_rule(pending | {"state":"unverified"})
            raise
        result=pending | {"state":"applied","verified_at":time.time()}
        self.store.put_rule(result)
        return result

    def remove(self,rid):
        rule=next((r for r in self.store.rules() if r["id"]==rid),None)
        if not rule:
            raise ValueError("Unknown Beaver rule")
        self.execute(rule["kind"],rule["target"],True)
        self.store.delete_rule(rid)
        return {"removed":rid}
