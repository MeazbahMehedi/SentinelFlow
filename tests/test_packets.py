import socket
import dpkt
import pytest
from sentinelflow.packets import make_demo,make_packet,read_capture,normalize_bytes


def test_demo_all_six_rules(tmp_path):
    from sentinelflow.detection import Detector
    from sentinelflow.db import DEFAULT_RULES,DEFAULT_SETTINGS
    events=read_capture(make_demo(tmp_path/'demo.pcap'))
    assert len(events)==501
    assert events==sorted(events,key=lambda e:e['ts'])
    d=Detector(DEFAULT_RULES,DEFAULT_SETTINGS)
    hits=[a for e in events for a in d.observe(e)]
    assert {a['rule'] for a in hits}==set(DEFAULT_RULES)
    assert len(hits)==6

@pytest.mark.parametrize('data',[b'',b'not a capture',b'\xd4\xc3\xb2\xa1'])
def test_invalid_capture(tmp_path,data):
    p=tmp_path/'bad.pcap';p.write_bytes(data)
    with pytest.raises(ValueError):read_capture(p)


def test_pcapng(tmp_path):
    p=tmp_path/'sample.pcapng'
    with p.open('wb') as f:
        w=dpkt.pcapng.Writer(f);w.writepkt(make_packet('10.0.0.1','10.0.0.2'),ts=100)
    events=read_capture(p)
    assert len(events)==1 and events[0]['src']=='10.0.0.1'


def test_ipv6():
    tcp=dpkt.tcp.TCP(sport=1234,dport=443,flags=2)
    ip=dpkt.ip6.IP6(src=socket.inet_pton(socket.AF_INET6,'2001:db8::1'),dst=socket.inet_pton(socket.AF_INET6,'2001:db8::2'),nxt=6,hlim=64,data=tcp)
    ip.plen=len(tcp)
    e=normalize_bytes(bytes(ip),100,101)
    assert e['proto']=='TCP' and e['src']=='2001:db8::1'


def test_dns_normalization():
    dns=bytes(dpkt.dns.DNS(id=1,qr=1,qd=[dpkt.dns.DNS.Q(name='example.test')]))
    e=normalize_bytes(make_packet('10.0.0.1','10.0.0.2',sport=53,dport=40000,udp=True,payload=dns),100)
    assert e['dns']=='example.test' and e['dns_response']

@pytest.mark.parametrize('linktype',[101,228])
def test_raw_ip(linktype):
    raw=make_packet('10.0.0.1','10.0.0.2')[14:]
    assert normalize_bytes(raw,100,linktype)['dst']=='10.0.0.2'


def test_capture_sorted(tmp_path):
    p=tmp_path/'reverse.pcap'
    with p.open('wb') as f:
        w=dpkt.pcap.Writer(f)
        for ts in [102,100,101]:w.writepkt(make_packet('10.0.0.1','10.0.0.2'),ts)
    assert [e['ts'] for e in read_capture(p)]==[100,101,102]


def test_unsupported_linktype():
    with pytest.raises(ValueError):normalize_bytes(b'abcd',100,999)


def test_multi_interface_pcapng_rejected(tmp_path):
    import struct
    p=tmp_path/'multi.pcapng'
    with p.open('wb') as f:
        w=dpkt.pcapng.Writer(f);w.writepkt(make_packet('10.0.0.1','10.0.0.2'),ts=100)
    raw=p.read_bytes()
    little=raw[8:12]==b'\x4d\x3c\x2b\x1a'
    endian='<' if little else '>'
    first_len=struct.unpack(endian+'I',raw[4:8])[0]
    idb_len=struct.unpack(endian+'I',raw[first_len+4:first_len+8])[0]
    idb=raw[first_len:first_len+idb_len]
    p.write_bytes(raw+idb)
    with pytest.raises(ValueError,match='multiple interfaces'):read_capture(p)
