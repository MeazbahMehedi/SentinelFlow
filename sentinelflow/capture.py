"""OS-aware passive capture diagnostics. Npcap is an external Windows driver."""
import os
import platform
from pathlib import Path
import threading
import time

_runtime_lock=threading.RLock()
_dll_directories=[]
_cache=None
_cache_at=0

class CaptureUnavailable(ValueError):
    pass


def windows_npcap_directory():
    directory=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32'/'Npcap'
    return directory if (directory/'wpcap.dll').is_file() and (directory/'Packet.dll').is_file() else None


def scapy_runtime():
    with _runtime_lock:
        windows=platform.system()=='Windows'
        if windows:
            directory=windows_npcap_directory()
            if directory is None:
                raise CaptureUnavailable('Npcap is not installed or its DLLs are unavailable. Install Npcap from https://npcap.com/#download, close Python, then reopen the terminal. If capture is restricted to administrators, run that terminal as Administrator.')
            if hasattr(os,'add_dll_directory') and not _dll_directories:
                _dll_directories.append(os.add_dll_directory(str(directory)))
        try:
            from scapy.all import conf,AsyncSniffer
            if windows:
                conf.use_pcap=True
                if not conf.use_pcap:
                    raise CaptureUnavailable('Npcap is installed but Scapy cannot load it. Repair Npcap, check that Python and Npcap architectures match, then restart Python.')
            return conf,AsyncSniffer
        except CaptureUnavailable:
            raise
        except Exception as exc:
            raise CaptureUnavailable('The capture backend could not initialize. Check OS capture permissions and restart Python after installing capture drivers. '+str(exc)[:140]) from exc


def capture_diagnostics(refresh=False):
    global _cache,_cache_at
    with _runtime_lock:
        if not refresh and _cache is not None and time.monotonic()-_cache_at<15:
            return dict(_cache)
        result={'platform':platform.system(),'ready':False,'interfaces':[],
                'message':'','driver':'Npcap' if platform.system()=='Windows' else 'OS packet capture',
                'help_url':'https://npcap.com/#download' if platform.system()=='Windows' else 'https://scapy.readthedocs.io/en/stable/installation.html',
                'note':'Backend availability is checked here. Interface permission is confirmed when capture starts.'}
        try:
            conf,_=scapy_runtime()
            conf.ifaces.reload()
            for iface in conf.ifaces.values():
                name=str(getattr(iface,'network_name','') or getattr(iface,'name',''))
                if not name:
                    continue
                description=str(getattr(iface,'description','') or getattr(iface,'name',name))
                address=str(getattr(iface,'ip','') or '')
                result['interfaces'].append({'id':name,'label':description,'address':address})
            result['ready']=bool(result['interfaces'])
            result['message']='Capture backend loaded. Choose an interface with visible traffic.' if result['ready'] else 'No capture interfaces were found. Check your adapter and capture permissions.'
        except CaptureUnavailable as exc:
            result['message']=str(exc)
        _cache=result;_cache_at=time.monotonic()
        return dict(result)


def open_capture_socket(iface):
    conf,sniffer_class=scapy_runtime()
    with _runtime_lock:
        conf.ifaces.reload()
        known={str(getattr(item,'network_name','') or getattr(item,'name','')) for item in conf.ifaces.values()}
        if iface not in known:
            raise CaptureUnavailable('That interface is no longer available. Refresh the capture check and select an adapter again.')
        try:
            # A passive layer 2 capture socket is required; an L3 sending socket is not a substitute.
            sock=conf.L2listen(iface=iface,promisc=False)
        except Exception as exc:
            message=str(exc).lower()
            if platform.system()=='Windows' and any(x in message for x in ('winpcap','npcap','layer 2','wpcap')):
                raise CaptureUnavailable('Npcap is unavailable to this Python process. Install or repair Npcap, close this server, reopen your terminal, and retry. Administrator-only Npcap installations require an elevated terminal.') from exc
            raise CaptureUnavailable('Cannot open this interface. Check capture permissions, whether the adapter is connected, and Npcap on Windows. '+str(exc)[:120]) from exc
        return sock,sniffer_class
