"""Event-time rules, scoped to a single monitoring session. No payload classification."""
from collections import defaultdict, deque
import ipaddress

RULE_INFO = {
 'port_scan': ('Possible port scan','high','Distinct destination ports contacted by a source and target pair.'),
 'host_scan': ('Possible host scan','high','Distinct destination hosts contacted by one source.'),
 'syn_burst': ('SYN burst indicator','high','TCP SYN packets without ACK from one source. This is a burst heuristic, not handshake reconstruction.'),
 'dns_burst': ('DNS query burst','medium','DNS queries from one source; resolver traffic can legitimately be high.'),
 'outbound_volume': ('Large outbound transfer','medium','Bytes from a configured local network to an address outside those networks.'),
 'indicator_match': ('Destination indicator match','critical','Destination IP matches your configured exact-match indicator list.'),
}

class Detector:
    def __init__(self,rules,settings):
        self.rules=rules
        self.indicators=set(settings['indicators'])
        self.networks=[ipaddress.ip_network(n,strict=False) for n in settings['local_networks']]
        self.windows=defaultdict(deque)
        self.last_alert={}
        self.clock=float('-inf')
        self.count=0

    def local(self, ip):
        address=ipaddress.ip_address(ip)
        return any(address.version==n.version and address in n for n in self.networks)

    def observe(self,e):
        # Never let a late event move the logical window clock backwards.
        if e['ts']<self.clock:
            return []
        now=max(self.clock,e['ts'])
        self.clock=now
        self.count+=1
        result=[]
        candidates=[('port_scan',(e['src'],e['dst']),e['dport'])] if e['proto'] in ('TCP','UDP') else []
        candidates.append(('host_scan',(e['src'],),e['dst']))
        if e['proto']=='TCP' and 'S' in e['flags'] and 'A' not in e['flags']:
            candidates.append(('syn_burst',(e['src'],),1))
        if e.get('dns') and not e.get('dns_response',False):
            candidates.append(('dns_burst',(e['src'],),1))
        if self.local(e['src']) and not self.local(e['dst']):
            candidates.append(('outbound_volume',(e['src'],),e['length']))
        if e['dst'] in self.indicators:
            candidates.append(('indicator_match',(e['src'],e['dst']),1))
        for rule,parts,value in candidates:
            cfg=self.rules[rule]
            if not cfg['enabled']:
                continue
            key=(rule,)+parts
            q=self.windows[key]
            cutoff=now-cfg['window']
            while q and q[0][0]<cutoff:
                q.popleft()
            # Very late packets remain visible in traffic but cannot affect expired windows.
            if e['ts']<cutoff:
                continue
            q.append((e['ts'],value))
            if rule in ('port_scan','host_scan'):
                observed=len({x[1] for x in q})
            elif rule=='outbound_volume':
                observed=sum(x[1] for x in q)
            else:
                observed=len(q)
            if observed>=cfg['threshold'] and now-self.last_alert.get(key,float('-inf'))>=cfg['window']:
                self.last_alert[key]=now
                title,severity,description=RULE_INFO[rule]
                result.append(dict(ts=e['ts'],rule=rule,severity=severity,src=e['src'],dst=e['dst'],title=title,
                    evidence={'observed':observed,'threshold':cfg['threshold'],'window_seconds':cfg['window'],
                    'description':description,'event_time':e['ts'],'note':'Rule indicator; investigate context before concluding malicious intent.'}))
        # Bound inactive state without retaining every source forever.
        if self.count%1000==0:
            for key in list(self.windows):
                cutoff=now-self.rules[key[0]]['window']
                q=self.windows[key]
                while q and q[0][0]<cutoff:
                    q.popleft()
                if not q:
                    del self.windows[key]
                    self.last_alert.pop(key,None)
        return result
