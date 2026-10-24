"""Offline parsing uses dpkt without opening any network socket.
Scapy is loaded only when live capture is requested.
"""
import math
import socket
import struct
from pathlib import Path
import dpkt

MAX_IMPORT_PACKETS=50000

def normalize_bytes(raw,ts,linktype=1):
    ts=float(ts)
    if not math.isfinite(ts) or ts<0 or ts>253402300799:
        raise ValueError('Invalid packet timestamp.')
    try:
        if linktype==1:
            layer=dpkt.ethernet.Ethernet(raw).data
        elif linktype==113:
            layer=dpkt.sll.SLL(raw).data
        elif linktype==276:
            if len(raw)<20:
                return None
            payload=raw[20:]
            layer=dpkt.ip6.IP6(payload) if payload[0]>>4==6 else dpkt.ip.IP(payload)
        elif linktype in (101,228,229):
            layer=dpkt.ip6.IP6(raw) if raw[0]>>4==6 else dpkt.ip.IP(raw)
        elif linktype in (0,108):
            payload=raw[4:]
            layer=dpkt.ip6.IP6(payload) if payload[0]>>4==6 else dpkt.ip.IP(payload)
        else:
            raise ValueError(f'Unsupported capture link type {linktype}. Use Ethernet, raw IP, loopback, or Linux cooked capture.')
        if not isinstance(layer,(dpkt.ip.IP,dpkt.ip6.IP6)):
            return None
        family=socket.AF_INET6 if isinstance(layer,dpkt.ip6.IP6) else socket.AF_INET
        event=dict(ts=ts,src=socket.inet_ntop(family,layer.src),dst=socket.inet_ntop(family,layer.dst),sport=0,dport=0,
            proto='OTHER',length=len(raw),flags='',dns='',dns_response=False)
        transport=layer.data
        if isinstance(transport,dpkt.tcp.TCP):
            flags=''.join(label for flag,label in [(1,'F'),(2,'S'),(4,'R'),(8,'P'),(16,'A'),(32,'U'),(64,'E'),(128,'C')] if transport.flags&flag)
            event.update(proto='TCP',sport=transport.sport,dport=transport.dport,flags=flags)
        elif isinstance(transport,dpkt.udp.UDP):
            event.update(proto='UDP',sport=transport.sport,dport=transport.dport)
            if 53 in (transport.sport,transport.dport):
                try:
                    dns=dpkt.dns.DNS(transport.data)
                    event['dns_response']=bool(dns.qr)
                    if dns.qd:
                        event['dns']=dns.qd[0].name[:253]
                except (dpkt.UnpackError,UnicodeError):
                    pass
        elif isinstance(transport,(dpkt.icmp.ICMP,dpkt.icmp6.ICMP6)):
            event['proto']='ICMP'
        return event
    except (dpkt.UnpackError,IndexError,ValueError) as exc:
        if isinstance(exc,ValueError) and str(exc).startswith('Unsupported'):
            raise
        # Truncated/unsupported packet payloads are skipped, not invented.
        return None

def normalize(pkt):
    if pkt.haslayer('Ether'):
        return normalize_bytes(bytes(pkt),float(pkt.time),1)
    layer=pkt.getlayer('IP') or pkt.getlayer('IPv6')
    return normalize_bytes(bytes(layer),float(pkt.time),101) if layer is not None else None

def validate_pcapng(f):
    """Reject mixed-interface captures instead of decoding them with the wrong link type."""
    interfaces=0
    sections=0
    endian=None
    while True:
        header=f.read(8)
        if not header:
            break
        if len(header)!=8:
            raise ValueError('Invalid packet capture block header.')
        if header[:4]==b'\x0a\x0d\x0d\x0a':
            sections+=1
            bom=f.read(4)
            if bom==b'\x4d\x3c\x2b\x1a':
                endian='<'
            elif bom==b'\x1a\x2b\x3c\x4d':
                endian='>'
            else:
                raise ValueError('Invalid packet capture byte order.')
            length=struct.unpack(endian+'I',header[4:])[0]
            if sections>1:
                raise ValueError('Unsupported PCAPNG with multiple sections. Export a single-interface capture.')
            remaining=length-12
        else:
            if not endian:
                raise ValueError('Invalid packet capture section.')
            block,length=struct.unpack(endian+'II',header)
            remaining=length-8
            if block==1:
                interfaces+=1
                if interfaces>1:
                    raise ValueError('Unsupported PCAPNG with multiple interfaces. Export each interface separately.')
        if length<12 or length%4 or length>33*1024*1024 or remaining<4:
            raise ValueError('Invalid packet capture block length.')
        body=f.read(remaining)
        if len(body)!=remaining or struct.unpack(endian+'I',body[-4:])[0]!=length:
            raise ValueError('Invalid packet capture truncated block.')
    f.seek(0)

def read_capture(path):
    events=[]
    try:
        with open(path,'rb') as f:
            magic=f.read(4)
            f.seek(0)
            if magic==b'\x0a\x0d\x0d\x0a':
                validate_pcapng(f)
                reader=dpkt.pcapng.Reader(f)
            else:
                reader=dpkt.pcap.Reader(f)
            linktype=reader.datalink()
            # Validate link type even for an otherwise empty capture.
            if linktype not in (0,1,101,108,113,228,229,276):
                raise ValueError(f'Unsupported capture link type {linktype}.')
            count=0
            for ts,raw in reader:
                count+=1
                if count>MAX_IMPORT_PACKETS:
                    raise ValueError(f'Capture exceeds {MAX_IMPORT_PACKETS:,} packets. Split it before importing.')
                event=normalize_bytes(raw,ts,linktype)
                if event:
                    events.append(event)
    except ValueError as exc:
        if str(exc).startswith(('Capture exceeds','Unsupported','Invalid packet')):
            raise
        raise ValueError('Unable to parse this capture. Upload a valid PCAP or PCAPNG file.') from exc
    except (dpkt.UnpackError,OSError,EOFError,TypeError) as exc:
        raise ValueError('Unable to parse this capture. Upload a valid PCAP or PCAPNG file.') from exc
    if not events:
        raise ValueError('No supported IPv4 or IPv6 packets were found in this capture.')
    return sorted(events,key=lambda e:e['ts'])

def make_packet(src,dst,sport=40000,dport=443,flags=dpkt.tcp.TH_ACK,payload=b'',udp=False):
    if udp:
        transport=dpkt.udp.UDP(sport=sport,dport=dport,data=payload)
        transport.ulen=len(transport)
    else:
        transport=dpkt.tcp.TCP(sport=sport,dport=dport,flags=flags,data=payload)
    ip=dpkt.ip.IP(src=socket.inet_aton(src),dst=socket.inet_aton(dst),p=17 if udp else 6,ttl=64,data=transport)
    ip.len=len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b'\x02\x00\x00\x00\x00\x01',dst=b'\x02\x00\x00\x00\x00\x02',type=0x800,data=ip))

def make_demo(path):
    packets=[]
    base=1760000000.0
    def add(raw,offset):
        packets.append((base+offset,raw))
    for i in range(60):
        add(make_packet(f'10.0.0.{10+i%4}','198.51.100.20',sport=42000+i,payload=b'x'*150),i*.13)
    for i in range(24):
        add(make_packet('10.0.0.45','10.0.0.100',dport=20+i,flags=2),8+i*.07)
    for i in range(16):
        add(make_packet('10.0.0.46',f'10.0.1.{i+1}',dport=445,flags=2),11+i*.07)
    for i in range(95):
        add(make_packet('10.0.0.47','10.0.0.100',sport=40000+i,dport=80,flags=2),14+i*.025)
    for i in range(75):
        dns=bytes(dpkt.dns.DNS(id=i,qd=[dpkt.dns.DNS.Q(name=f'query{i}.example.test')]))
        add(make_packet('10.0.0.48','10.0.0.1',sport=45000+i,dport=53,payload=dns,udp=True),18+i*.03)
    for i in range(230):
        add(make_packet('10.0.0.49','198.51.100.25',sport=50000,dport=9000,payload=b'd'*1200,udp=True),23+i*.02)
    add(make_packet('10.0.0.50','203.0.113.66',sport=50100,flags=2),29)
    with open(path,'wb') as f:
        writer=dpkt.pcap.Writer(f)
        for ts,raw in sorted(packets,key=lambda p:p[0]):
            writer.writepkt(raw,ts)
    return Path(path)
