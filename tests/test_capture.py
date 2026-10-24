from types import SimpleNamespace
import pytest
import sentinelflow.capture as capture
from sentinelflow.packets import make_packet,normalize


def test_missing_npcap_actionable(monkeypatch):
    monkeypatch.setattr(capture.platform,'system',lambda:'Windows')
    monkeypatch.setattr(capture,'windows_npcap_directory',lambda:None)
    result=capture.capture_diagnostics(refresh=True)
    assert not result['ready'] and 'Install Npcap' in result['message']
    assert result['interfaces']==[]


def test_friendly_interfaces(monkeypatch):
    class Interfaces(dict):
        def reload(self):pass
    conf=SimpleNamespace(ifaces=Interfaces(a=SimpleNamespace(network_name='adapter-1',name='eth0',description='Ethernet adapter',ip='10.0.0.3')))
    monkeypatch.setattr(capture,'scapy_runtime',lambda:(conf,object))
    result=capture.capture_diagnostics(refresh=True)
    assert result['ready'] and result['interfaces'][0]['label']=='Ethernet adapter'


def test_bad_interface_rejected(monkeypatch):
    class Interfaces(dict):
        def reload(self):pass
    conf=SimpleNamespace(ifaces=Interfaces(a=SimpleNamespace(network_name='adapter-1')))
    monkeypatch.setattr(capture,'scapy_runtime',lambda:(conf,object))
    with pytest.raises(capture.CaptureUnavailable,match='no longer available'):capture.open_capture_socket('unknown')


def test_npcap_error_converted(monkeypatch):
    class Interfaces(dict):
        def reload(self):pass
    def fail(**kwargs):raise RuntimeError('Sniffing at layer 2: winpcap is not installed')
    conf=SimpleNamespace(ifaces=Interfaces(a=SimpleNamespace(network_name='adapter-1')),L2listen=fail)
    monkeypatch.setattr(capture,'scapy_runtime',lambda:(conf,object))
    monkeypatch.setattr(capture.platform,'system',lambda:'Windows')
    with pytest.raises(capture.CaptureUnavailable,match='Install or repair Npcap'):capture.open_capture_socket('adapter-1')


def test_loopback_normalizes_inner_ip():
    class Packet:
        time=100
        def haslayer(self,name):return False
        def getlayer(self,name):return make_packet('10.0.0.1','10.0.0.2')[14:] if name=='IP' else None
    event=normalize(Packet())
    assert event['proto']=='TCP' and event['src']=='10.0.0.1'


def test_capture_api(client,monkeypatch):
    monkeypatch.setattr(capture,'capture_diagnostics',lambda **kw:{'ready':False,'interfaces':[],'message':'Install Npcap'})
    result=client.get('/api/capture/status')
    assert result.status_code==200 and not result.json['ready']


def test_live_session_limit_checked_before_socket(app,monkeypatch):
    store=app.extensions['store'];engine=app.extensions['engine']
    with store.connect() as c:
        c.executemany("INSERT INTO sessions(name,source,created) VALUES(?,'live',0)",[(str(i),) for i in range(100)])
    def forbidden(*args):raise AssertionError('A socket must not open when the session limit is reached.')
    monkeypatch.setattr('sentinelflow.engine.open_capture_socket',forbidden)
    with pytest.raises(ValueError,match='Session limit reached'):engine.start_live('eth0')
