import ipaddress
import io
import json
import socket
import struct
import subprocess
import time
from unittest.mock import patch

import psutil
import pytest
from backend.binaries import location, publisher
from backend.capture import Capture
from backend.firewall import LOCKDOWN_PORTS, Firewall, FirewallError, linux_script, ps_literal, rule_id, validate, windows_script
from backend.intelligence import FEEDS, Intelligence, parse
from backend.monitor import Monitor
from backend.risk import assess, beacon, remote_tool
from backend.service import Service
from backend.storage import Store

FEED = {f["id"]: f for f in FEEDS}

@pytest.fixture
def store(tmp_path):
    value=Store(tmp_path)
    yield value
    value.close()

class Intel:
    """Deterministic stand-in for the feed matcher."""
    def __init__(self, ips=None, domains=None, fresh=True):
        self.ips=ips or {}; self.domains=domains or {}; self.is_fresh=fresh
    def hit(self, value, points, feed="feodo"):
        return {"feed":feed,"name":feed,"category":"Fixture category","points":points,"source":"https://example.invalid","malware":"x","value":value}
    def match(self, ip):
        return [self.hit(ip,*self.ips[ip])] if ip in self.ips and self.is_fresh else []
    def match_domain(self, domain):
        return [self.hit(domain,self.domains[domain],"threat-domains")] if domain in self.domains and self.is_fresh else []
    def fresh(self):
        return self.is_fresh

@pytest.fixture
def intel():
    return Intel()

def app(path="/usr/bin/browser", name="Browser"):
    return {"path":path,"name":name}

def connection(ip="1.1.1.1",port=443,**extra):
    return {"remote_ip":ip,"remote_port":port,"protocol":"TCP","local_port":50000,"local_ip":"192.168.1.2","status":"ESTABLISHED"}|extra

def rules(result):
    return {e["rule"] for e in result["evidence"]}

# --- Risk model -------------------------------------------------------------------------------------------

def test_unknown_without_intelligence():
    assert assess(app(),[connection()],Intel(fresh=False),10)["level"]=="Unknown"

def test_unknown_without_identity_or_observation(intel):
    assert assess(app(None),[],intel,100)["level"]=="Unknown"
    assert assess(app(),[],intel,1)["level"]=="Unknown"

def test_low_is_not_a_safety_verdict(intel):
    result=assess(app(),[connection()],intel,3,context={"system":"Linux"})
    assert result["level"]=="Low" and "not a safety guarantee" in result["reason"]

def test_c2_match_is_high_even_when_allowlisted():
    result=assess(app(),[connection()],Intel({"1.1.1.1":(90,)}),3,True,{"1.1.1.1"})
    assert result["level"]=="High" and result["score"]==90 and result["evidence"][0]["endpoint"]=="1.1.1.1"

def test_reputation_feeds_alone_are_medium_and_inbound_scans_are_discounted():
    outbound=assess(app(),[connection()],Intel({"1.1.1.1":(45,"et-compromised")}),5,context={"system":"Linux"})
    assert outbound["level"]=="Medium"
    inbound=assess(app(),[connection(local_port=8080)],Intel({"1.1.1.1":(45,"et-compromised")}),5,
                   context={"system":"Linux","listening":{("TCP",8080)}})
    assert inbound["score"]==11 and inbound["level"]=="Low"

def test_multiple_malicious_endpoints_add_bounded_points():
    hits=Intel({f"1.1.1.{i}":(45,"ipsum") for i in range(10)})
    result=assess(app(),[connection(f"1.1.1.{i}") for i in range(10)],hits,5,context={"system":"Linux"})
    assert result["intel_score"]==60

def test_domain_intel_matches_observed_domain():
    result=assess(app(),[connection(domain="bad.example")],Intel(domains={"bad.example":80}),5,context={"system":"Linux"})
    assert result["level"]=="High" and "intel-domain" in rules(result)

def test_stale_feed_does_not_escalate():
    assert assess(app(),[connection()],Intel({"1.1.1.1":(90,)},fresh=False),10)["level"]=="Unknown"

def test_port_fanout_and_allowlist(intel):
    connections=[connection(port=p) for p in range(30)]
    ctx={"system":"Linux"}
    assert assess(app(),connections,intel,10,context=ctx)["level"]=="Medium"
    assert assess(app(),connections,intel,10,True,context=ctx)["level"]=="Low"
    assert assess(app(),connections,intel,10,False,{"1.1.1.1"},context=ctx)["level"]=="Low"

def test_common_tls_not_suspicious(intel):
    conns=[connection(str(ipaddress.IPv4Address(0x08080800+i)),443) for i in range(25)]
    assert assess(app(),conns,intel,10,context={"system":"Linux"})["score"]==0

def test_temporary_executable_alone_is_not_high(intel):
    result=assess(app("C:\\Users\\Test\\AppData\\Local\\Temp\\installer.exe","installer.exe"),[connection()],intel,10,context={"system":"Windows"})
    assert result["score"]==20 and result["level"]=="Low"

def test_masquerading_system_process_from_wrong_folder(intel):
    fake=assess(app("C:\\Users\\Public\\svchost.exe","svchost.exe"),[connection()],intel,10,context={"system":"Windows"})
    assert {"masquerading","temporary-executable"}<=rules(fake) and fake["level"]=="High"
    real=assess(app("C:\\Windows\\System32\\svchost.exe","svchost.exe"),[connection()],intel,10,context={"system":"Windows"})
    assert "masquerading" not in rules(real)

def test_verified_publisher_reduces_behavior_but_not_intel():
    ctx={"system":"Windows","binary":{"signature":"valid","publisher":"Contoso","location":"system"}}
    beaconing=[float(t) for t in range(0,300,30)]
    result=assess(app("C:\\Program Files\\A\\a.exe","a.exe"),[connection()],Intel(),10,context=ctx|{"beacons":{("1.1.1.1",443):beaconing}})
    assert result["score"]==15 and "verified-publisher" in rules(result)
    c2=assess(app("C:\\Program Files\\A\\a.exe","a.exe"),[connection()],Intel({"1.1.1.1":(90,)}),10,context=ctx)
    assert c2["level"]=="High"

def test_tampered_signature_and_untrusted_signature(intel):
    tampered=assess(app("C:\\Tools\\x.exe","x.exe"),[connection()],intel,10,context={"system":"Windows","binary":{"signature":"tampered","location":"user"}})
    assert tampered["score"]==50 and tampered["level"]=="Medium"

def test_lolbin_and_document_parent(intel):
    ctx={"system":"Windows","parent":"WINWORD.EXE"}
    result=assess(app("C:\\Windows\\System32\\mshta.exe","mshta.exe"),[connection()],intel,10,context=ctx)
    assert {"lolbin-network","document-spawned"}<=rules(result) and result["level"]=="Medium"
    local=assess(app("C:\\Windows\\System32\\mshta.exe","mshta.exe"),[connection("192.168.1.1")],intel,10,context={"system":"Windows"})
    assert "lolbin-network" not in rules(local)

def test_beacon_detection():
    assert beacon([0,30,60,90,120,150])==30
    assert beacon([0,30,61,89,121,150])  # sampling jitter
    assert beacon([0,5,60,61,200,201]) is None
    assert beacon([0,1,2,3,4,5]) is None  # too fast to be a beacon
    assert beacon([0,30,60]) is None

def test_linux_fileless_and_deleted_executables(intel):
    assert "fileless" in rules(assess(app("/memfd:x","x"),[connection()],intel,10,context={"system":"Linux","fileless":True}))
    assert assess(app("/dev/shm/.x","x"),[connection()],intel,10,context={"system":"Linux","deleted":True})["level"]=="High"

def test_suspicious_ports(intel):
    assert "suspicious-port" in rules(assess(app(),[connection(port=4444)],intel,10,context={"system":"Linux"}))
    assert "tor-port" in rules(assess(app(),[connection(port=9001)],intel,10,context={"system":"Linux"}))
    assert "tor-port" not in rules(assess(app("/usr/bin/tor","tor"),[connection(port=9001)],intel,10,context={"system":"Linux"}))

# --- Remote access and data theft --------------------------------------------------------------------------

def test_remote_access_tool_is_flagged_even_when_signed(intel):
    ctx={"system":"Windows","binary":{"signature":"valid","publisher":"AnyDesk Software GmbH","location":"system"}}
    result=assess(app("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe","AnyDesk.exe"),[connection()],intel,10,context=ctx)
    assert result["level"]=="Medium" and result["remote_tool"]=="AnyDesk" and "remote-access-tool" in rules(result)
    allowed=assess(app("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe","AnyDesk.exe"),[connection()],intel,10,True,context=ctx)
    assert allowed["level"]=="Low" and allowed["remote_tool"]=="AnyDesk"
    assert remote_tool("TeamViewer_Service.exe")=="TeamViewer" and remote_tool("notepad.exe") is None

def test_inbound_rdp_from_internet_is_high_but_lan_is_not(intel):
    ctx={"system":"Windows","listening":{("TCP",3389)}}
    listener=connection(None,None,local_port=3389,local_ip="0.0.0.0",status="LISTEN")
    internet=assess(app("C:\\Windows\\System32\\svchost.exe","svchost.exe"),[listener,connection("45.33.32.156",51515,local_port=3389)],intel,10,context=ctx)
    assert internet["level"]=="High" and "inbound-remote-login" in rules(internet)
    lan=assess(app("C:\\Windows\\System32\\svchost.exe","svchost.exe"),[listener,connection("192.168.1.9",51515,local_port=3389)],intel,10,context=ctx)
    assert "inbound-remote-login" not in rules(lan) and "exposed-remote-service" in rules(lan)

def test_reverse_shell(intel):
    result=assess(app("/usr/bin/bash","bash"),[connection(port=4444)],intel,10,context={"system":"Linux"})
    assert {"reverse-shell","suspicious-port"}<=rules(result) and result["level"]=="High"
    cmd=assess(app("C:\\Windows\\System32\\cmd.exe","cmd.exe"),[connection()],intel,10,context={"system":"Windows"})
    assert "reverse-shell" in rules(cmd)

def test_exfiltration_channels(intel):
    stealer=assess(app("C:\\Users\\a\\Downloads\\free.exe","free.exe"),[connection(domain="api.telegram.org")],intel,10,
                   context={"system":"Windows","binary":{"signature":"unsigned","location":"staging"}})
    assert "exfil-channel" in rules(stealer) and stealer["score"]==65 and stealer["level"]=="Medium"
    telegram=assess(app("C:\\Users\\a\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe","Telegram.exe"),[connection(domain="api.telegram.org")],intel,10,context={"system":"Windows"})
    assert "exfil-channel" not in rules(telegram)
    browser=assess(app("C:\\Program Files\\Mozilla Firefox\\firefox.exe","firefox.exe"),[connection(domain="transfer.sh")],intel,10,context={"system":"Windows"})
    assert "exfil-channel" not in rules(browser)

# --- Threat feeds -------------------------------------------------------------------------------------------

def test_feed_parsers():
    assert parse(FEED["feodo"],b"[]")==set()
    assert int(ipaddress.ip_address("1.1.1.1")) in parse(FEED["feodo"],json.dumps([{"ip_address":"1.1.1.1"}]))
    for bad in (b"{}",b"[{}]",json.dumps([{"ip_address":"127.0.0.1"}]),json.dumps([{"ip_address":"not-an-ip"}])):
        with pytest.raises((ValueError,KeyError)):
            parse(FEED["feodo"],bad)
    starts,ends=parse(FEED["spamhaus-drop"],b'{"cidr":"1.10.16.0/20","sblid":"x"}\n{"type":"metadata"}\n')
    assert ends[0]-starts[0]==4095
    with pytest.raises(ValueError):
        parse(FEED["spamhaus-drop"],b'{"cidr":"0.0.0.0/0"}')
    assert len(parse(FEED["ipsum"],b"# comment\n8.8.4.4\n\n9.9.9.9 7\n"))==2

def write_feed(tmp_path, feed_id, body, updated=None):
    folder=tmp_path/"feeds"; folder.mkdir(exist_ok=True)
    (folder/(feed_id+".txt")).write_bytes(body)
    (folder/(feed_id+".json")).write_text(json.dumps({"updated":updated or time.time()}))

def test_cidr_and_domain_matching_from_cache(tmp_path):
    write_feed(tmp_path,"spamhaus-drop",b'{"cidr":"1.10.16.0/20"}\n')
    write_feed(tmp_path,"threat-domains",b"# header\nevil.example\n")
    intel=Intelligence(tmp_path)
    assert intel.match("1.10.31.255")[0]["feed"]=="spamhaus-drop" and intel.match("1.10.32.0")==[]
    assert intel.match_domain("cdn.evil.example")[0]["points"]==80 and intel.match_domain("example")==[]
    assert intel.match("not-an-ip")==[] and intel.match("10.0.0.1")==[]
    intel.set_disabled(["spamhaus-drop"]); assert intel.match("1.10.16.1")==[]

def test_stale_feed_is_not_matched(tmp_path):
    write_feed(tmp_path,"feodo",json.dumps([{"ip_address":"1.1.1.1"}]).encode(),time.time()-FEED["feodo"]["max_age"]-1)
    intel=Intelligence(tmp_path)
    assert intel.match("1.1.1.1")==[] and not intel.fresh() and intel.status()["feeds"][0]["entries"]==1

def test_feed_failure_keeps_previous_cache(tmp_path):
    write_feed(tmp_path,"feodo",json.dumps([{"ip_address":"1.1.1.1"}]).encode())
    intel=Intelligence(tmp_path)
    with patch("urllib.request.urlopen",side_effect=OSError("offline")):
        with pytest.raises(ValueError): intel.refresh()
    assert intel.match("1.1.1.1") and intel.errors["feodo"]=="offline" and intel.status()["error"]

# --- Storage ------------------------------------------------------------------------------------------------

def test_settings_validation_and_persistence(store):
    assert store.set_settings({"retention_days":3})["retention_days"]==3
    for patch_value in ({"retention_days":0},{"capture":"true"},{"unknown":True},{"retention_days":True},
                        {"disabled_feeds":["nope"]},{"snoozed_until":time.time()+30*86400},{"active_protection":1}):
        with pytest.raises(ValueError): store.set_settings(patch_value)
    assert store.settings()["capture"] is False and store.settings()["remote_alerts"] is True
    assert store.set_settings({"disabled_feeds":["ipsum"]})["disabled_feeds"]==["ipsum"]

def test_history_pagination_closure_and_sql_safety(store):
    now=time.time()
    rows=[{"id":str(i),"app_id":"app' OR 1=1--","first_seen":now,"last_seen":now,"remote_ip":"1.1.1.1"} for i in range(5)]
    store.connections(rows,[("0",now)])
    result=store.history("app' OR 1=1--",0,2)
    assert result["total"]==5 and len(result["items"])==2
    assert store.history("unrelated")["total"]==0
    assert any(i["ended"] for i in store.history("app' OR 1=1--",0,100)["items"])

def test_alert_dedup_escalation_and_acknowledgement(store):
    alert={"id":"first","app_id":"a","created":time.time(),"key":"a|Medium|beaconing","level":"Medium"}
    assert store.add_alert(alert)
    assert not store.add_alert(alert | {"id":"second"})
    assert store.add_alert(alert | {"id":"third","key":"a|High|beaconing,known-c2","level":"High"})
    assert store.alert_counts()=={"Medium":1,"High":1}
    store.acknowledge("first"); assert store.alert_counts()=={"High":1}
    store.acknowledge("*"); assert all(a["acknowledged"] for a in store.alerts())

def test_binary_cache_invalidates_on_replacement(store,tmp_path):
    exe=tmp_path/"tool.exe"; exe.write_bytes(b"v1")
    st=exe.stat(); first=store.put_binary({"path":str(exe),"size":st.st_size,"mtime":int(st.st_mtime),"sha256":"x"})
    assert store.binary(str(exe))["first_seen"]==first
    exe.write_bytes(b"version two"); assert store.binary(str(exe)) is None

def test_allowlist_remove(store):
    entry={"id":"a","kind":"endpoint","target":"1.1.1.1"}
    store.allow(entry,True); assert store.allowlist()==[entry]
    store.allow(entry,False); assert store.allowlist()==[]

# --- Executable inspection ----------------------------------------------------------------------------------

def test_location_and_publisher_parsing():
    assert location("C:\\Users\\a\\AppData\\Local\\Temp\\x.exe","Windows")=="staging"
    assert location("C:\\Users\\a\\Downloads\\x.exe","Windows")=="staging"
    assert location("C:\\Program Files\\App\\a.exe","Windows")=="system"
    assert location("C:\\Users\\a\\AppData\\Local\\Programs\\code\\Code.exe","Windows")=="user"
    assert location("/dev/shm/x","Linux")=="memory" and location("/usr/bin/curl","Linux")=="system" and location("/tmp/x","Linux")=="staging"
    assert publisher('CN="Microsoft Corporation", O=Microsoft')=="Microsoft Corporation" and publisher("") is None

# --- Firewall -----------------------------------------------------------------------------------------------

def test_firewall_rejects_injection_and_dangerous_targets():
    for target in ("1.1.1.1; reboot","127.0.0.1","::1","0.0.0.0","224.0.0.1","1.1.1.1\n"):
        with pytest.raises(ValueError): validate("endpoint",target)
    assert validate("endpoint","2606:4700:4700::1111")=="2606:4700:4700::1111"
    with pytest.raises(ValueError): validate("application","/bin/sh","Linux")
    for ports in ("3389;calc","0","70000","",",".join(map(str,range(1,40)))):
        with pytest.raises(ValueError): validate("ports",ports)
    assert validate("ports","5900, 3389,3389")=="3389,5900"

def test_powershell_literal_escaping():
    assert ps_literal("C:\\it's\\app.exe") == "'C:\\it''s\\app.exe'"
    script=windows_script("endpoint","1.1.1.1")
    assert "-Action Block" in script and "-Direction Inbound" in script and "-Direction Outbound" in script
    assert "Remove-NetFirewallRule" in script and "catch" in script

def test_lockdown_rule_is_inbound_tcp_only():
    script=windows_script("ports",LOCKDOWN_PORTS)
    assert "-Direction Inbound" in script and "-Direction Outbound" not in script and "-LocalPort 23,3389" in script
    nft=linux_script("ports","3389,5900")
    assert "tcp dport { 3389, 5900 } drop" in nft and "output" not in nft and 'iifname != "lo"' in nft

def test_nft_rules_are_scoped_and_ipv6_correct():
    script=linux_script("endpoint","2606:4700:4700::1111")
    assert "ip6 daddr" in script and "ip6 saddr" in script and "flush ruleset" not in script
    assert "delete table inet beaver_" in linux_script("endpoint","1.1.1.1",True)

def test_failed_firewall_action_never_claims_success(store):
    fake=lambda *args,**kwargs: subprocess.CompletedProcess(args,1,"","authorization cancelled")
    fw=Firewall(store,fake); fw.system="Windows"
    with pytest.raises(FirewallError): fw.apply("endpoint","1.1.1.1")
    assert store.rules()[0]["state"]=="unverified"
    assert store.rules()[0]["verified_at"] is None

def test_firewall_apply_remove_only_own_id(store):
    fake=lambda *args,**kwargs: subprocess.CompletedProcess(args,0,"","")
    fw=Firewall(store,fake); fw.system="Windows"
    rule=fw.apply("endpoint","1.1.1.1")
    assert rule["state"]=="applied" and len(store.rules())==1
    fw.apply("endpoint","1.1.1.1"); assert len(store.rules())==1
    with pytest.raises(ValueError): fw.remove("foreign-rule")
    fw.remove(rule["id"]); assert not store.rules()

def test_linux_rules_from_before_reboot_are_inactive_and_reapply(store):
    calls=[]
    runner=lambda args,**kw: calls.append(args) or subprocess.CompletedProcess(args,0,"","")
    fw=Firewall(store,runner,boot_time=lambda: 0); fw.system="Linux"
    with patch("shutil.which",return_value="/usr/sbin/nft"), patch("os.geteuid",create=True,return_value=0):
        assert fw.apply("endpoint","1.1.1.1")["state"]=="applied"
        booted=time.time()+0.001; fw.boot_time=lambda: booted  # machine restarted after the rule was applied
        assert fw.rules()[0]["state"]=="inactive"
        time.sleep(0.01)
        assert fw.apply("endpoint","1.1.1.1")["state"]=="applied" and len(calls)==2 and fw.rules()[0]["state"]=="applied"

def test_verify_marks_missing_rules(store):
    calls=[]
    def runner(args,**kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args,0,json.dumps(["Beaver-"+rule_id("endpoint","1.1.1.1")+"-In"]) if "Get-NetFirewallRule" in args[-1] else "","")
    fw=Firewall(store,runner); fw.system="Windows"
    fw.apply("endpoint","1.1.1.1"); fw.apply("endpoint","2.2.2.2")
    states={r["target"]:r["state"] for r in fw.verify()["rules"]}
    assert states=={"1.1.1.1":"applied","2.2.2.2":"missing"}
    assert fw.apply("endpoint","2.2.2.2")["state"]=="applied"  # a missing rule can be re-applied

# --- Capture ------------------------------------------------------------------------------------------------

def owned(app_id="a",protocol="TCP",pid=123):
    return {"app_id":app_id,"pid":pid,"protocol":protocol,"local_ip":"192.168.1.2","local_port":50000,"remote_ip":"1.1.1.1","remote_port":443}

def test_capture_exact_tuple_and_ambiguity():
    cap=Capture(); cap.update_owners([owned()])
    assert cap.owner("TCP","192.168.1.2",50000,"1.1.1.1",443)=="a"
    assert cap.owner("TCP","192.168.1.2",50000,"8.8.8.8",443) is None
    cap.update_owners([owned(),owned("b")])
    assert cap.owner("TCP","192.168.1.2",50000,"1.1.1.1",443) is None

def frame(src,dst,sport,dport,proto=6,payload=b"",vlan=False):
    """Ethernet + IPv4 + TCP/UDP frame built byte by byte."""
    l4=struct.pack("!HH",sport,dport)+(b"\0"*16 if proto==6 else struct.pack("!HH",8+len(payload),0))+payload
    ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(l4),0,0,64,proto,0,socket.inet_aton(src),socket.inet_aton(dst))
    tag=struct.pack("!HH",0x8100,7) if vlan else b""
    return b"\0"*12+tag+struct.pack("!H",0x0800)+ip+l4

def dns_response(name,ip):
    labels=b"".join(bytes([len(p)])+p.encode() for p in name.split("."))+b"\0"
    answer=b"\xc0\x0c"+struct.pack("!HHIH",1,1,300,4)+socket.inet_aton(ip)
    return struct.pack("!HHHHHH",1,0x8180,1,1,0,0)+labels+struct.pack("!HH",1,1)+answer

def test_capture_direction_bytes_and_no_payload_retention():
    cap=Capture();cap.update_owners([owned()])
    packet=frame("192.168.1.2","1.1.1.1",50000,443,payload=b"not retained")
    cap.handle(1,packet)
    totals,flows,_=cap.snapshot()
    assert totals["a"][0]==len(packet)-14 and totals["a"][1]==0 and len(flows)==1
    cap.handle(1,frame("1.1.1.1","192.168.1.2",443,50000,vlan=True))
    assert cap.snapshot()[0]["a"][1]>0
    assert "not retained" not in repr(cap.__dict__)

def test_header_parser_handles_ipv6_raw_and_garbage():
    from backend.pcap import parse
    v6=struct.pack("!IHBB",6<<28,8,17,64)+socket.inet_pton(socket.AF_INET6,"2001:db8::1")+socket.inet_pton(socket.AF_INET6,"2606:4700::1")+struct.pack("!HHHH",5353,53,8,0)
    assert parse(101,v6)[:5]==("UDP","2001:db8::1",5353,"2606:4700::1",53)
    assert parse(1,b"\0"*13) is None and parse(1,b"\xff"*60) is None and parse(999,frame("1.1.1.1","2.2.2.2",1,2)) is None

def test_dns_answers_are_parsed_with_compression():
    cap=Capture(); cap.handle(1,frame("8.8.8.8","192.168.1.2",53,5000,17,dns_response("Evil.Example.com","9.9.9.9")))
    assert cap.snapshot()[2]=={"9.9.9.9":"evil.example.com"}
    cap.handle(1,frame("8.8.8.8","192.168.1.2",53,5000,17,b"\x00\x01\x81\x80\x00\x01\x00\x05\xc0\x0c"))  # truncated and looping

def client_hello(name, padding=0):
    """Minimal TLS 1.2 record carrying a ClientHello with an optional padding extension before SNI."""
    sni=name.encode(); server_name=struct.pack("!HBH",len(sni)+3,0,len(sni))+sni
    ext=(struct.pack("!HH",21,padding)+b"\0"*padding if padding else b"")+struct.pack("!HH",0,len(server_name))+server_name
    body=b"\x03\x03"+b"\x11"*32+b"\x00"+struct.pack("!H",2)+b"\x13\x01"+b"\x01\x00"+struct.pack("!H",len(ext))+ext
    handshake=b"\x01"+len(body).to_bytes(3,"big")+body
    return b"\x16\x03\x01"+struct.pack("!H",len(handshake))+handshake

def tcp_frame(src,dst,sport,dport,payload):
    l4=struct.pack("!HHIIBBHHH",sport,dport,0,0,0x50,0x18,65535,0,0)+payload
    ip=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(l4),0,0,64,6,0,socket.inet_aton(src),socket.inet_aton(dst))
    return b"\0"*12+struct.pack("!H",0x0800)+ip+l4

def test_tls_server_name_from_client_hello():
    from backend.pcap import client_hello as parse_hello
    assert parse_hello(client_hello("Login.Example.org"))[1]=="login.example.org"
    assert parse_hello(b"\x17\x03\x03\x00\x10") is None  # application data, not a handshake
    cap=Capture(); frame=tcp_frame("192.168.1.2","93.184.216.34",50000,443,client_hello("www.example.com"))
    cap.handle(1,frame[:128],lambda: frame)  # header-only prefix plus on-demand full frame, like the live reader
    assert cap.snapshot()[2]=={"93.184.216.34":"www.example.com"} and cap.server_names==1

def test_tls_server_name_split_across_segments():
    hello=client_hello("split.example.net",padding=1600); cut=1200
    cap=Capture()
    cap.handle(1,tcp_frame("192.168.1.2","1.2.3.4",50001,443,hello[:cut]))
    assert cap.snapshot()[2]=={} and cap.hellos
    cap.handle(1,tcp_frame("192.168.1.2","1.2.3.4",50001,443,hello[cut:]))
    assert cap.snapshot()[2]=={"1.2.3.4":"split.example.net"} and not cap.hellos

def test_udp_unique_wildcard_binding():
    cap=Capture(); row=owned(protocol="UDP") | {"local_ip":"0.0.0.0","remote_ip":None,"remote_port":None}
    cap.update_owners([row]); assert cap.owner("UDP","192.168.1.2",50000,"8.8.8.8",53)=="a"
    cap.update_owners([row,row | {"app_id":"b"}]); assert cap.owner("UDP","192.168.1.2",50000,"8.8.8.8",53) is None

# --- Service and live monitor -------------------------------------------------------------------------------

def test_unknown_rpc_and_invalid_parameters(tmp_path):
    service=Service(tmp_path)
    try:
        with pytest.raises(ValueError): service.dispatch("execute_shell",{})
        with pytest.raises(ValueError): service.dispatch("snapshot",[])
        with pytest.raises(ValueError): service.dispatch("allowlist",{"kind":"endpoint","target":"1.1.1.1","enabled":"yes"})
        with pytest.raises(ValueError): service.dispatch("terminate",{"app_id":"not-running"})
    finally: service.store.close()

def test_events_are_pushed_as_lines(tmp_path):
    output=io.StringIO(); service=Service(tmp_path,output)
    try:
        service.emit("alert",{"id":"x"}); service.handle({"id":7,"method":"visibility","params":{"visible":False}})
        lines=[json.loads(l) for l in output.getvalue().splitlines()]
        assert lines[0]=={"event":"alert","data":{"id":"x"}} and lines[1]=={"id":7,"result":{"ok":True}}
        assert service.monitor.visible is False
    finally: service.store.close()

def test_terminate_refuses_core_and_foreign_processes(store):
    monitor=Monitor(store)
    me=psutil.Process()
    monitor.state={"apps":[{"id":"core","name":"lsass.exe","pids":[me.pid],"binary":{},"risk":{}},
                           {"id":"self","name":"python","pids":[me.pid],"binary":{},"risk":{}}]}
    with pytest.raises(ValueError, match="core operating-system"): monitor.terminate("core")
    with pytest.raises(ValueError): monitor.terminate("self")  # Beaver never stops itself
    assert me.is_running()

def test_live_local_socket_is_observed_and_retained(store):
    listener=socket.socket(); listener.bind(("127.0.0.1",0)); listener.listen()
    client=socket.create_connection(listener.getsockname()); server,_=listener.accept()
    events=[]; monitor=Monitor(store,lambda e,d: events.append(e))
    try:
        monitor.sample()
        snapshot=monitor.snapshot(); assert snapshot["ready"]
        rows=[c for c in snapshot["connections"] if c["pid"]==psutil.Process().pid and c["local_port"]==listener.getsockname()[1]]
        assert rows, "Real local socket was not present in OS telemetry"
        assert store.history(rows[0]["app_id"])["total"]>=1
        assert all(a["download_bps"] is None for a in snapshot["apps"])
        assert "status" in events
        monitor.sample(); assert monitor.snapshot()["connections"][0]["first_seen"]<=time.time()
    finally:
        client.close(); server.close(); listener.close(); monitor.stop()

def test_permission_error_keeps_last_good_inventory(store):
    monitor=Monitor(store); monitor.sample(); before=dict(monitor.current)
    with patch("psutil.net_connections",side_effect=psutil.AccessDenied()):
        with pytest.raises(RuntimeError): monitor.sample()
    assert monitor.current==before
    monitor.stop()

def test_first_internet_is_recorded_once_and_learning_is_silent(store):
    assert store.learning()  # fresh install
    assert store.first_internet("C:\\a.exe") and not store.first_internet("C:\\a.exe")

def live_app(path="C:\\Tools\\new.exe", binary=None):
    return {"id":"n1","name":"new.exe","path":path,"binary":binary or {"state":"inspected","signature":"unsigned"}}

def test_new_app_alert_after_learning(store):
    events=[]; monitor=Monitor(store,lambda e,d: events.append(d))
    conns=[connection("8.8.8.8",443,domain="dns.google",geo=None)]
    store.installed_at=time.time()-10_000
    monitor.new_app(live_app(),conns,time.time())
    alert=store.alerts()[0]
    assert alert["level"]=="Info" and alert["kind"]=="new-app" and alert["endpoint"]["domain"]=="dns.google" and events
    monitor.new_app(live_app(),conns,time.time()); assert len(store.alerts())==1  # once per path
    monitor.new_app(live_app("C:\\Windows\\System32\\x.exe",{"state":"inspected","os_binary":True}),conns,time.time())
    monitor.new_app(live_app("C:\\Tools\\lan.exe"),[connection("192.168.1.9",445,domain=None,geo=None)],time.time())
    monitor.new_app(live_app("C:\\Tools\\wait.exe",{"state":"pending"}),conns,time.time())
    assert len(store.alerts())==1 and "C:\\Tools\\wait.exe" not in store.known_apps
    monitor.stop()

def test_new_apps_during_learning_are_recorded_silently(store):
    monitor=Monitor(store)
    monitor.new_app(live_app(),[connection("8.8.8.8",443,domain=None,geo=None)],time.time())
    assert store.alerts()==[] and "C:\\Tools\\new.exe" in store.known_apps
    monitor.stop()

def test_sampling_slows_on_battery_only_without_a_window(store):
    monitor=Monitor(store); battery=type("B",(),{"power_plugged":False})()
    with patch("psutil.sensors_battery",return_value=battery):
        monitor.visible=False; assert monitor.interval()==4
        monitor.visible=True; assert monitor.interval()==2
    monitor.stop()
