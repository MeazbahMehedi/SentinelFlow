"""One background capture/replay worker per process; run one application process."""
import json
import queue
import threading
import time
from .detection import Detector
from .packets import normalize
from .capture import open_capture_socket

class Engine:
    def __init__(self,store):
        self.store=store
        self.lock=threading.RLock()
        self.worker=None
        self.active_id=None
        self.stop_event=threading.Event()
        self.paused=False
        self.speed=1.0

    def _available(self):
        if self.worker and self.worker.is_alive():
            raise ValueError('Stop the active monitoring or replay session first.')

    def import_events(self,name,events,source='pcap'):
        with self.store.connect() as c:
            sid=c.execute('INSERT INTO sessions(name,source,total,created) VALUES(?,?,?,?)',(name,source,len(events),time.time())).lastrowid
            c.executemany('INSERT INTO replay_packets VALUES(?,?,?)',[(sid,i,json.dumps(e)) for i,e in enumerate(events)])
        self.store.audit('capture_import',f'Session {sid}: {len(events)} supported packets')
        return sid

    def _prepare(self,sid,speed):
        self.stop_event=threading.Event()
        self.paused=False
        self.speed=speed
        self.active_id=sid
        rules=self.store.config('rules')
        settings=self.store.config('settings')
        with self.store.connect() as c:
            c.execute('DELETE FROM packets WHERE session_id=?',(sid,))
            c.execute('DELETE FROM alerts WHERE session_id=?',(sid,))
            c.execute("UPDATE sessions SET status='running',processed=0,error='',dropped=0,speed=?,rule_snapshot=? WHERE id=?",(speed,json.dumps({'rules':rules,'settings':settings}),sid))
        return Detector(rules,settings)

    def start_replay(self,sid,speed=1):
        with self.lock:
            self._available()
            row=self.store.one('SELECT * FROM sessions WHERE id=?',(sid,))
            if not row or row['source'] not in ('pcap','demo'):
                raise ValueError('Select a replayable capture.')
            detector=self._prepare(sid,speed)
            self.worker=threading.Thread(target=self._replay,args=(sid,detector),daemon=True,name='pcap-replay')
            self.worker.start()
        self.store.audit('replay_start',str(sid))

    def _wait(self,delta):
        remaining=max(0,delta)
        while remaining>0 and not self.stop_event.is_set():
            if self.paused:
                self.stop_event.wait(.05)
                continue
            step=min(.05,remaining/max(.25,self.speed))
            start=time.monotonic()
            if self.stop_event.wait(step):
                return False
            if not self.paused:
                remaining-=(time.monotonic()-start)*self.speed
        while self.paused and not self.stop_event.is_set():
            self.stop_event.wait(.05)
        return not self.stop_event.is_set()

    def _replay(self,sid,detector):
        try:
            events=self.store.rows('SELECT event FROM replay_packets WHERE session_id=? ORDER BY seq',(sid,))
            last=None
            for row in events:
                e=json.loads(row['event'])
                if not self._wait(e['ts']-last if last is not None else 0):
                    break
                self.ingest(sid,e,detector)
                last=e['ts']
            self.store.execute('UPDATE sessions SET status=? WHERE id=?',('stopped' if self.stop_event.is_set() else 'finished',sid))
        except Exception as exc:
            self._error(sid,exc)

    def ingest(self,sid,e,detector):
        # Fail closed at a retained-packet ceiling rather than silently dropping history.
        if self.store.one('SELECT COUNT(*) AS n FROM packets')['n']>=self.store.config('settings')['max_packets']:
            raise ValueError('Retained packet limit reached. Delete an old session in Settings before continuing.')
        alerts=detector.observe(e)
        with self.store.connect() as c:
            c.execute('INSERT INTO packets(session_id,ts,src,dst,sport,dport,proto,length,flags,dns) VALUES(?,?,?,?,?,?,?,?,?,?)',
                (sid,e['ts'],e['src'],e['dst'],e['sport'],e['dport'],e['proto'],e['length'],e['flags'],e['dns']))
            for a in alerts:
                c.execute('INSERT INTO alerts(session_id,ts,rule,severity,src,dst,title,evidence) VALUES(?,?,?,?,?,?,?,?)',
                    (sid,a['ts'],a['rule'],a['severity'],a['src'],a['dst'],a['title'],json.dumps(a['evidence'])))
            c.execute('UPDATE sessions SET processed=processed+1 WHERE id=?',(sid,))

    def _error(self,sid,exc):
        self.store.execute("UPDATE sessions SET status='error',error=? WHERE id=?",(str(exc)[:400],sid))
        self.store.audit('worker_error',f'{sid}: {str(exc)[:250]}')

    def control(self,sid,action,speed=None):
        with self.lock:
            if sid!=self.active_id or not self.worker or not self.worker.is_alive():
                raise ValueError('This session is not active.')
            if action=='pause':
                if self.store.one('SELECT source FROM sessions WHERE id=?',(sid,))['source']=='live':
                    raise ValueError('Live capture cannot be paused. Stop it instead.')
                self.paused=True
                self.store.execute("UPDATE sessions SET status='paused' WHERE id=?",(sid,))
            elif action=='resume':
                self.paused=False
                self.store.execute("UPDATE sessions SET status='running' WHERE id=?",(sid,))
            elif action=='stop':
                self.stop_event.set()
            elif action=='speed' and speed is not None:
                self.speed=speed
                self.store.execute('UPDATE sessions SET speed=? WHERE id=?',(speed,sid))
            else:
                raise ValueError('Unknown session action.')

    def start_live(self,iface):
        with self.lock:
            self._available()
            if self.store.one('SELECT COUNT(*) n FROM sessions')['n']>=100:
                raise ValueError('Session limit reached. Delete an older session before starting capture.')
            sock,sniffer_class=open_capture_socket(iface)
            try:
                sid=self.store.execute("INSERT INTO sessions(name,source,total,created) VALUES(?,'live',0,?)",(f'Live · {iface}',time.time()))
                detector=self._prepare(sid,1)
                self.worker=threading.Thread(target=self._live,args=(sid,detector,sock,sniffer_class),daemon=True,name='live-capture')
                self.worker.start()
            except Exception:
                sock.close()
                raise
        self.store.audit('live_start',iface)
        return sid

    def _live(self,sid,detector,sock,sniffer_class):
        pending=queue.Queue(maxsize=5000)
        dropped=[0]
        def callback(pkt):
            try:
                event=normalize(pkt)
                if event:
                    pending.put_nowait(event)
            except queue.Full:
                dropped[0]+=1
            except Exception:
                dropped[0]+=1
        sniffer=sniffer_class(opened_socket=sock,store=False,prn=callback)
        try:
            sniffer.start()
            while not self.stop_event.is_set():
                if getattr(sniffer,'exception',None):
                    raise RuntimeError(str(sniffer.exception))
                try:
                    event=pending.get(timeout=.2)
                    self.ingest(sid,event,detector)
                except queue.Empty:
                    pass
            self.store.execute("UPDATE sessions SET status='stopped' WHERE id=?",(sid,))
        except Exception as exc:
            self._error(sid,exc)
        finally:
            try:
                if sniffer.running:
                    sniffer.stop()
            except Exception as exc:
                self.store.audit('capture_cleanup',str(exc)[:200])
            finally:
                sock.close()
            # Queue contents remaining at Stop were captured but not analyzed.
            self.store.execute('UPDATE sessions SET dropped=? WHERE id=?',(dropped[0]+pending.qsize(),sid))

    def shutdown(self):
        self.stop_event.set()
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=3)
