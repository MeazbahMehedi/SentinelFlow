from copy import deepcopy
import pytest
from sentinelflow.db import DEFAULT_RULES,DEFAULT_SETTINGS
from sentinelflow.detection import Detector


def event(**kwargs):
    e=dict(ts=100,src='10.0.0.10',dst='10.0.0.20',sport=45000,dport=443,proto='TCP',length=100,flags='A',dns='',dns_response=False)
    e.update(kwargs)
    return e

@pytest.fixture
def detector():
    return Detector(deepcopy(DEFAULT_RULES),deepcopy(DEFAULT_SETTINGS))

@pytest.mark.parametrize('rule',['port_scan','host_scan','syn_burst','dns_burst','outbound_volume','indicator_match'])
def test_rules_trigger_with_evidence(rule):
    rules=deepcopy(DEFAULT_RULES)
    for key in rules:
        rules[key]['enabled']=key==rule
    rules[rule]['threshold']=3 if rule!='outbound_volume' else 250
    d=Detector(rules,DEFAULT_SETTINGS)
    hits=[]
    for i in range(3):
        kwargs=dict(ts=100+i*.1)
        if rule=='port_scan':kwargs['dport']=80+i
        if rule=='host_scan':kwargs['dst']=f'10.0.0.{20+i}'
        if rule=='syn_burst':kwargs['flags']='S'
        if rule=='dns_burst':kwargs.update(proto='UDP',dns='example.test')
        if rule in ('outbound_volume','indicator_match'):kwargs['dst']='203.0.113.66'
        hits+=d.observe(event(**kwargs))
    assert len(hits)==1
    assert hits[0]['rule']==rule
    assert hits[0]['evidence']['observed']>=hits[0]['evidence']['threshold']


def test_normal_traffic_no_alert(detector):
    assert not [a for i in range(50) for a in detector.observe(event(ts=100+i*.1))]


def test_window_expiration(detector):
    for i in range(20):
        assert not detector.observe(event(ts=100+i*31,dport=100+i))


def test_threshold_boundary_and_duplicate_suppression(detector):
    for i in range(11):
        assert not detector.observe(event(dport=100+i,ts=100+i*.1))
    assert detector.observe(event(dport=111,ts=101.1))[0]['rule']=='port_scan'
    assert not detector.observe(event(dport=112,ts=101.2))


def test_disabled_rule():
    rules=deepcopy(DEFAULT_RULES)
    for rule in rules.values():rule['enabled']=False
    d=Detector(rules,DEFAULT_SETTINGS)
    assert not d.observe(event(dst='203.0.113.66',flags='S'))


def test_syn_ack_not_counted(detector):
    assert not [a for i in range(100) for a in detector.observe(event(ts=100+i*.01,flags='SA'))]


def test_dns_answers_not_queries(detector):
    assert not [a for i in range(100) for a in detector.observe(event(ts=100+i*.01,proto='UDP',dns='example.test',dns_response=True))]


def test_late_event_does_not_rewind_window(detector):
    detector.observe(event(ts=1000))
    assert not detector.observe(event(ts=100,dst='203.0.113.66'))
    assert detector.clock==1000


def test_ipv6_local_config():
    settings=deepcopy(DEFAULT_SETTINGS);settings['local_networks']=['fd00::/8']
    d=Detector(DEFAULT_RULES,settings)
    assert d.local('fd00::1')
    assert not d.local('2001:db8::1')
