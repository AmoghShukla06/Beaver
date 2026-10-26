"""Run ONLY inside a disposable unshare -Urn network namespace, never on the host."""
import json
import os
import socket
import subprocess
import tempfile
from backend.firewall import Firewall
from backend.storage import Store

# Parent PID's namespace must differ: fail closed before any mutation.
baseline=os.environ.get('BEAVER_HOST_NETNS')
if not baseline or os.readlink('/proc/self/ns/net') == baseline:
    raise SystemExit('Refusing to change firewall in the host namespace')
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','addr','add','192.0.2.1/32','dev','lo'],check=True)
subprocess.run(['nft','add','table','inet','beaver_unrelated_test'],check=True)
server=socket.socket();server.bind(('192.0.2.1',0));server.listen(10)
address=server.getsockname()
def connects():
    try:
        with socket.create_connection(address,timeout=.5): return True
    except (TimeoutError,OSError): return False
with tempfile.TemporaryDirectory(prefix='beaver-nft-') as directory:
    store=Store(directory);fw=Firewall(store)
    assert connects(), 'Baseline local test connection failed'
    rule=fw.apply('endpoint','192.0.2.1')
    assert not connects(), 'Native nft rule did not block the endpoint'
    fw.remove(rule['id'])
    assert connects(), 'Connection did not recover after rule removal'
    subprocess.run(['nft','list','table','inet','beaver_unrelated_test'],check=True,capture_output=True)
    print(json.dumps({'native_nft_block':True,'unblock':True,'unrelated_rules_preserved':True,'scope':'disposable network namespace'}))
    store.close()
server.close()
