"""SentinelFlow application factory."""
import atexit
import csv
import io
import ipaddress
import json
import os
import sqlite3
from pathlib import Path
import secrets
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for, stream_with_context
from PIL import Image, UnidentifiedImageError
from werkzeug.exceptions import HTTPException
from werkzeug.local import LocalProxy
from .accounts import canonical_gmail
from werkzeug.security import check_password_hash, generate_password_hash
from .db import Store
from .detection import RULE_INFO
from .engine import Engine
from .packets import make_demo, read_capture

PAGES={'overview':('Overview','Your network, in focus.'),'traffic':('Live traffic','Follow every connection.'),
 'alerts':('Threat alerts','Signals worth investigating.'),'replay':('PCAP replay','Turn captures into a live investigation.'),
 'hosts':('Host explorer','Know the devices behind the traffic.'),'analytics':('Analytics','Understand the shape of your network.'),
 'rules':('Detection rules','Make every signal explainable.'),'team':('The developers','Built with curiosity. Designed for clarity.'),
 'repositories':('GitHub projects','Follow the work behind the developers.'),
 'settings':('Settings','A workspace that works your way.')}

def create_app(test_config=None):
    app=Flask(__name__,instance_relative_config=True)
    root=Path(os.getenv('SENTINELFLOW_DATA',str(Path.cwd()/'instance')))
    if test_config:
        root=Path(test_config.get('DATA_DIR',root))
    root.mkdir(parents=True,exist_ok=True)
    secret_path=root/'secret.key'
    if not secret_path.exists():
        try:
            with secret_path.open('x') as f:
                f.write(secrets.token_hex(32))
            secret_path.chmod(0o600)
        except FileExistsError:
            pass
    app.config.update(SECRET_KEY=os.getenv('SECRET_KEY') or secret_path.read_text().strip(),MAX_CONTENT_LENGTH=33*1024*1024,
        SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE')=='1',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),DATA_DIR=root,MAX_FORM_MEMORY_SIZE=200000,
        TRUSTED_HOSTS=[x.strip() for x in os.getenv('TRUSTED_HOSTS','localhost,127.0.0.1,[::1]').split(',') if x.strip()])
    if test_config:
        app.config.update(test_config)
    identities=Store(root/'sentinelflow.db')
    primary_engine=Engine(identities)
    workspace_lock=threading.RLock()
    workspaces={}
    stopping=threading.Event()

    def workspace_for(uid):
        uid=int(uid)
        with workspace_lock:
            first=identities.one('SELECT MIN(id) AS id FROM users')['id']
            if uid==first:
                return identities,primary_engine
            if not identities.one('SELECT id FROM users WHERE id=?',(uid,)):
                raise ValueError('Unknown account.')
            if uid not in workspaces:
                directory=root/'workspaces'/str(uid)
                directory.mkdir(parents=True,exist_ok=True)
                private_store=Store(directory/'workspace.db')
                workspaces[uid]=(private_store,Engine(private_store))
            return workspaces[uid]

    def shutdown():
        stopping.set()
        with workspace_lock:
            engines=[primary_engine]+[e for _,e in workspaces.values()]
        # Signal every worker before waiting for any of them.
        for item in engines:
            item.stop_event.set()
        for item in engines:
            item.shutdown()

    def request_workspace():
        return workspace_for(session['uid']) if session.get('uid') else (identities,primary_engine)
    store=LocalProxy(lambda:request_workspace()[0])
    engine=LocalProxy(lambda:request_workspace()[1])
    app.extensions.update(store=identities,engine=primary_engine,workspace_for=workspace_for,
                          shutdown=shutdown,stopping=stopping,identities=identities)
    atexit.register(shutdown)
    auth_lock=threading.Lock()
    attempts={}
    setup_lock=threading.Lock()
    (root/'media').mkdir(exist_ok=True)
    (root/'tmp').mkdir(exist_ok=True)
    from .github import GitHubProjects
    github_projects=GitHubProjects(root/'github-cache')
    app.extensions['github_projects']=github_projects

    def csrf():
        if 'csrf' not in session:
            session['csrf']=secrets.token_hex(24)
        return session['csrf']

    @app.context_processor
    def context():
        current_user=identities.one('SELECT id,username,email,role FROM users WHERE id=?',(session.get('uid',0),))
        return dict(csrf_token=csrf,pages=PAGES,current_page=request.endpoint,rule_info=RULE_INFO,
                    current_user=current_user,is_admin=bool(current_user and current_user['role']=='admin'))

    @app.template_filter('utc')
    def utc(value):
        if value is None:
            return '—'
        try:
            return datetime.fromtimestamp(float(value),timezone.utc).strftime('%d %b %Y · %H:%M:%S')
        except (OverflowError,ValueError,OSError):
            return 'Invalid timestamp'

    @app.template_filter('bytes')
    def human_bytes(n):
        n=float(n or 0)
        for unit in ['B','KB','MB','GB']:
            if n<1024 or unit=='GB':
                return f'{n:,.1f} {unit}' if unit!='B' else f'{n:,.0f} B'
            n/=1024

    @app.before_request
    def protect():
        if request.endpoint=='static':
            return
        if request.method=='POST':
            token=request.form.get('csrf_token') or request.headers.get('X-CSRF-Token','')
            if not secrets.compare_digest(str(token),str(session.get('csrf','missing'))):
                abort(400,description='Your form expired. Refresh the page and try again.')
        if session.get('uid') and not identities.one('SELECT id FROM users WHERE id=?',(session['uid'],)):
            session.clear()
        has_user=bool(identities.one('SELECT id FROM users LIMIT 1'))
        if not has_user and request.endpoint not in ('setup','register','static'):
            return redirect(url_for('setup'))
        if has_user and request.endpoint=='setup':
            return redirect(url_for('overview') if session.get('uid') else url_for('login'))
        if has_user and not session.get('uid') and request.endpoint not in ('login','setup','register','static'):
            if request.path.startswith('/api/'):
                return jsonify(error='Authentication required.'),401
            return redirect(url_for('login'))

    @app.after_request
    def headers(response):
        response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
            'Referrer-Policy':'same-origin','Cache-Control':'no-store',
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https://avatars.githubusercontent.com; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"})
        return response

    @app.errorhandler(HTTPException)
    def http_error(e):
        if request.path.startswith('/api/'):
            return jsonify(error=e.description),e.code
        return render_template('error.html',code=e.code,message=e.description),e.code

    def sign_in(user):
        session.clear()
        session.update(uid=user['id'],username=user['username'],permanent=True)

    def create_account(first=False):
        username=request.form.get('username','').strip()
        password=request.form.get('password','')
        email=canonical_gmail(request.form.get('email',''))
        if not 3<=len(username)<=40 or not 12<=len(password)<=128:
            raise ValueError('Use a username of 3–40 characters and a password of 12–128 characters.')
        if '@' in username or any(ord(ch)<32 for ch in username):
            raise ValueError('Your username cannot contain @ or control characters.')
        with setup_lock:
            if first and identities.one('SELECT id FROM users LIMIT 1'):
                raise ValueError('An administrator already exists. Use Create account instead.')
            if identities.one('SELECT id FROM users WHERE email=?',(email,)):
                raise ValueError('This Gmail address already has an account. Sign in instead.')
            if identities.one('SELECT id FROM users WHERE lower(username)=lower(?)',(username,)):
                raise ValueError('That username is already in use.')
            try:
                uid=identities.execute('INSERT INTO users(username,password,email,role) VALUES(?,?,?,?)',
                    (username,generate_password_hash(password),email,'admin' if first else 'analyst'))
            except sqlite3.IntegrityError as exc:
                raise ValueError('That Gmail address or username already has an account.') from exc
        return identities.one('SELECT * FROM users WHERE id=?',(uid,))

    @app.route('/setup',methods=['GET','POST'])
    def setup():
        if request.method=='POST':
            try:
                user=create_account(first=True)
                sign_in(user)
                store.audit('workspace_created',user['username'])
                return redirect(url_for('overview'))
            except ValueError as exc:
                flash(str(exc),'error')
        return render_template('auth.html',mode='setup')

    @app.route('/register',methods=['GET','POST'])
    def register():
        if not identities.one('SELECT id FROM users LIMIT 1'):
            return redirect(url_for('setup'))
        if request.method=='POST':
            try:
                user=create_account()
                sign_in(user)
                store.audit('account_created','Private workspace initialized')
                return redirect(url_for('overview'))
            except ValueError as exc:
                flash(str(exc),'error')
        return render_template('auth.html',mode='register')

    @app.route('/login',methods=['GET','POST'])
    def login():
        if request.method=='POST':
            remote=request.remote_addr or 'local'
            with auth_lock:
                now=time.time()
                for key in list(attempts):
                    attempts[key]=[x for x in attempts[key] if now-x<300]
                    if not attempts[key]:
                        del attempts[key]
                recent=attempts.setdefault(remote,[])
                if len(recent)>=10:
                    abort(429,description='Too many login attempts. Try again in five minutes.')
                recent.append(now)
            identity=request.form.get('username','').strip()
            if '@' in identity:
                try:
                    identity=canonical_gmail(identity)
                except ValueError:
                    pass
                user=identities.one('SELECT * FROM users WHERE email=?',(identity,))
            else:
                user=identities.one('SELECT * FROM users WHERE lower(username)=lower(?)',(identity,))
            if user and check_password_hash(user['password'],request.form.get('password','')):
                with auth_lock:
                    attempts.pop(remote,None)
                sign_in(user)
                return redirect(url_for('overview'))
            flash('Gmail, username, or password is incorrect.','error')
        return render_template('auth.html',mode='login')

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    def selected():
        raw=request.args.get('session','')
        if not raw:
            return None
        try:
            sid=int(raw)
        except ValueError:
            abort(400,description='Invalid session filter.')
        if not store.one('SELECT id FROM sessions WHERE id=?',(sid,)):
            abort(404,description='Session not found.')
        return sid

    def where(sid,alias=''):
        return (f' WHERE {alias}session_id=?',[sid]) if sid else ('',[])

    def summary(sid=None):
        w,args=where(sid)
        totals=store.one('SELECT COUNT(*) packets,COALESCE(SUM(length),0) bytes,COUNT(DISTINCT src) sources,COUNT(DISTINCT src||\':\'||sport||\'>\'||dst||\':\'||dport||\':\'||proto) connections,MIN(ts) first,MAX(ts) last FROM packets'+w,args)
        hosts=store.one('SELECT COUNT(*) n FROM (SELECT src ip FROM packets'+w+' UNION SELECT dst ip FROM packets'+w+')',args+args)['n']
        totals['hosts']=hosts
        totals['alerts']=store.one('SELECT COUNT(*) n FROM alerts'+w,args)['n']
        extra=' AND ' if w else ' WHERE '
        totals['open_alerts']=store.one('SELECT COUNT(*) n FROM alerts'+w+extra+"status IN ('new','investigating')",args)['n']
        protocols=store.rows('SELECT proto label,COUNT(*) value,SUM(length) bytes FROM packets'+w+' GROUP BY proto ORDER BY value DESC',args)
        series=[]
        if totals['first'] is not None:
            span=max(1,totals['last']-totals['first'])
            width=max(1,span/39)
            buckets=store.rows('SELECT CAST((ts-?)/? AS INTEGER) bucket,COUNT(*) packets,SUM(length) bytes FROM packets'+w+' GROUP BY bucket ORDER BY bucket',[totals['first'],width]+args)
            by={b['bucket']:b for b in buckets}
            series=[dict(ts=totals['first']+i*width,packets=by.get(i,{}).get('packets',0),bytes=by.get(i,{}).get('bytes',0)) for i in range(max(by)+1)]
        return dict(totals=totals,protocols=protocols,series=series,sessions=store.rows('SELECT * FROM sessions ORDER BY id DESC LIMIT 100'),
            alerts=store.rows('SELECT * FROM alerts'+w+' ORDER BY id DESC LIMIT 8',args))

    def page_data(page):
        sid=selected()
        data=summary(sid)
        data.update(page=page,title=PAGES[page][0],subtitle=PAGES[page][1],selected=sid)
        w,args=where(sid)
        if page in ('traffic','alerts'):
            conditions=['session_id=?'] if sid else []
            args=[sid] if sid else []
            q=request.args.get('q','')[:150]
            if q:
                fields=['src','dst','proto','dns'] if page=='traffic' else ['src','dst','title','rule']
                conditions.append('('+' OR '.join(f'{f} LIKE ?' for f in fields)+')')
                args.extend(['%'+q+'%']*len(fields))
            status=request.args.get('status','')
            severity=request.args.get('severity','')
            if page=='alerts' and status in ('new','investigating','resolved','false_positive'):
                conditions.append('status=?');args.append(status)
            if page=='alerts' and severity in ('critical','high','medium','low'):
                conditions.append('severity=?');args.append(severity)
            clause=' WHERE '+' AND '.join(conditions) if conditions else ''
            table='packets' if page=='traffic' else 'alerts'
            count=store.one(f'SELECT COUNT(*) n FROM {table}'+clause,args)['n']
            try:
                number=max(1,int(request.args.get('p',1)))
            except ValueError:
                number=1
            number=min(number,max(1,(count+49)//50))
            data.update(records=store.rows(f'SELECT * FROM {table}'+clause+' ORDER BY id DESC LIMIT 50 OFFSET ?',args+[(number-1)*50]),count=count,number=number,total_pages=max(1,(count+49)//50),q=q,status=status,severity=severity)
        if page in ('hosts','analytics'):
            data['hosts']=store.rows('SELECT ip,SUM(sent) sent,SUM(received) received,SUM(n) packets FROM (SELECT src ip,SUM(length) sent,0 received,COUNT(*) n FROM packets'+w+' GROUP BY src UNION ALL SELECT dst ip,0 sent,SUM(length) received,COUNT(*) n FROM packets'+w+' GROUP BY dst) GROUP BY ip ORDER BY sent+received DESC LIMIT 100',args+args)
            data['rule_counts']=store.rows('SELECT rule,COUNT(*) n FROM alerts'+w+' GROUP BY rule ORDER BY n DESC',args)
            data['severity_counts']=store.rows('SELECT severity,COUNT(*) n FROM alerts'+w+' GROUP BY severity',args)
        if page=='rules':
            data.update(rules=store.config('rules'),settings=store.config('settings'))
        if page=='repositories':
            from .github import DEVELOPERS
            data['github_developers']=DEVELOPERS
        if page=='team':
            data['profiles']=identities.rows('SELECT * FROM profiles ORDER BY id')
        if page=='settings':
            data.update(settings=store.config('settings'),audit=store.rows('SELECT * FROM audit ORDER BY id DESC LIMIT 30'))
            if identities.one('SELECT role FROM users WHERE id=?',(session['uid'],))['role']=='admin':
                data['accounts']=identities.rows('SELECT id,username,email,role FROM users ORDER BY id LIMIT 1000')
        if page=='replay':
            from .capture import capture_diagnostics
            admin=identities.one('SELECT role FROM users WHERE id=?',(session['uid'],))['role']=='admin'
            data['capture_status']=capture_diagnostics() if admin else {'ready':False,'interfaces':[],'message':'Live host capture requires an administrator account. You can import and replay your own PCAP files.','platform':'','help_url':'https://scapy.readthedocs.io/en/stable/installation.html'}
            data['interfaces']=data['capture_status']['interfaces']
        return data

    def get_interfaces():
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return []

    for page in PAGES:
        def view(page=page):
            return render_template(page+'.html',**page_data(page))
        app.add_url_rule('/' if page=='overview' else '/'+page,endpoint=page,view_func=view)

    @app.get('/api/github/<login>')
    def github_repositories(login):
        from .github import DEVELOPERS
        if login not in DEVELOPERS:
            abort(404)
        return jsonify(github_projects.repositories(login))

    @app.get('/api/snapshot')
    def snapshot():
        return jsonify(summary(selected()))

    @app.get('/api/packets')
    def packet_feed():
        w,args=where(selected())
        return jsonify(store.rows('SELECT * FROM packets'+w+' ORDER BY id DESC LIMIT 50',args))

    @app.get('/api/stream')
    def stream():
        sid=selected()
        @stream_with_context
        def events():
            # Finite stream permits session revalidation on automatic EventSource reconnect.
            for _ in range(60):
                if stopping.is_set():
                    break
                yield 'data: '+json.dumps(summary(sid))+'\n\n'
                if stopping.wait(1):
                    break
        return Response(events(),mimetype='text/event-stream',headers={'X-Accel-Buffering':'no'})

    @app.post('/replay/upload')
    def upload():
        f=request.files.get('capture')
        if not f or not f.filename or Path(f.filename).suffix.lower() not in ('.pcap','.pcapng','.cap'):
            flash('Choose a PCAP, PCAPNG, or CAP capture.','error')
            return redirect(url_for('replay'))
        path=None
        try:
            with tempfile.NamedTemporaryFile(dir=root/'tmp',delete=False,suffix='.pcap') as temp:
                path=Path(temp.name)
                f.save(temp)
            if path.stat().st_size>32*1024*1024:
                raise ValueError('The capture limit is 32 MiB.')
            if store.one('SELECT COUNT(*) n FROM sessions')['n']>=100:
                raise ValueError('Session limit reached. Delete an older session first.')
            sid=engine.import_events(Path(f.filename.replace('\\','/')).name[:100],read_capture(path))
            flash('Capture imported. Press Start to replay it.','success')
            return redirect(url_for('replay',session=sid))
        except ValueError as exc:
            flash(str(exc),'error')
            return redirect(url_for('replay'))
        finally:
            if path:
                path.unlink(missing_ok=True)

    @app.post('/replay/eve')
    def eve_upload():
        from .integrations import read_eve,import_eve
        f=request.files.get('eve')
        if not f or not f.filename:
            abort(400,description='Select an EVE JSON file.')
        path=root/'tmp'/f'{secrets.token_hex(12)}.json'
        try:
            if store.one('SELECT COUNT(*) n FROM sessions')['n']>=100:
                raise ValueError('Delete an older session before importing another.')
            f.save(path)
            if path.stat().st_size>32*1024*1024:
                raise ValueError('EVE file limit is 32 MiB.')
            sid=import_eve(store,Path(f.filename.replace('\\','/')).name[:100],read_eve(path))
            flash('Suricata alerts imported. This session contains alerts, not packet evidence.','success')
            return redirect(url_for('alerts',session=sid))
        except (ValueError,UnicodeError) as exc:
            flash(str(exc),'error')
            return redirect(url_for('replay'))
        finally:
            path.unlink(missing_ok=True)

    @app.post('/replay/demo')
    def demo():
        if store.one('SELECT COUNT(*) n FROM sessions')['n']>=100:
            abort(400,description='Delete an older session before importing another.')
        path=root/'tmp'/f'{secrets.token_hex(12)}.pcap'
        try:
            make_demo(path)
            sid=engine.import_events('Guided threat simulation',read_capture(path),'demo')
        finally:
            path.unlink(missing_ok=True)
        flash('Demonstration capture loaded. Start replay at 4× for a quick walkthrough.','success')
        return redirect(url_for('replay',session=sid))

    def speed_value():
        try:
            speed=float(request.form.get('speed','1'))
        except ValueError:
            raise ValueError('Invalid replay speed.')
        if speed not in (.25,.5,1,2,4,8,16,32):
            raise ValueError('Choose one of the supported replay speeds.')
        return speed

    @app.post('/sessions/<int:sid>/<action>')
    def control(sid,action):
        try:
            if action=='start':
                engine.start_replay(sid,speed_value())
            else:
                engine.control(sid,action,speed_value() if action=='speed' else None)
            flash('Session command accepted.','success')
        except ValueError as exc:
            flash(str(exc),'error')
        return redirect(url_for('replay',session=sid))

    def require_admin():
        if identities.one('SELECT role FROM users WHERE id=?',(session['uid'],))['role']!='admin':
            abort(403,description='This action requires an administrator account.')

    @app.post('/accounts/<int:uid>/role')
    def account_role(uid):
        require_admin()
        role=request.form.get('role','')
        if role not in ('admin','analyst') or uid==session['uid']:
            abort(400,description='Choose a valid role for another account. You cannot change your own role.')
        if not identities.one('SELECT id FROM users WHERE id=?',(uid,)):
            abort(404)
        identities.execute('UPDATE users SET role=? WHERE id=?',(role,uid))
        if role=='analyst':
            other_store,other_engine=workspace_for(uid)
            with other_engine.lock:
                active=other_store.one('SELECT source FROM sessions WHERE id=?',(other_engine.active_id,))
                if active and active['source']=='live' and other_engine.worker and other_engine.worker.is_alive():
                    other_engine.stop_event.set()
        store.audit('account_role_changed',f'Account {uid}: {role}')
        flash('Account permissions updated.','success')
        return redirect(url_for('settings'))

    @app.get('/api/capture/status')
    def capture_status():
        require_admin()
        from .capture import capture_diagnostics
        return jsonify(capture_diagnostics(refresh=True))

    @app.post('/live/start')
    def live_start():
        require_admin()
        try:
            sid=engine.start_live(request.form.get('interface',''))
            flash('Live monitoring started.','success')
            return redirect(url_for('replay',session=sid))
        except Exception as exc:
            flash('Capture could not start. '+str(exc)[:600],'error')
            return redirect(url_for('replay'))

    @app.get('/alerts/<int:aid>')
    def alert_detail(aid):
        alert=store.one('SELECT * FROM alerts WHERE id=?',(aid,))
        if not alert:
            abort(404)
        alert['evidence']=json.loads(alert['evidence'])
        session_row=store.one('SELECT * FROM sessions WHERE id=?',(alert['session_id'],))
        window=alert['evidence']['window_seconds']
        related=store.rows('SELECT * FROM packets WHERE session_id=? AND src=? AND ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT 100',
            (alert['session_id'],alert['src'],alert['ts']-window,alert['ts']))
        others=store.rows('SELECT * FROM alerts WHERE session_id=? AND src=? AND id<>? ORDER BY ts LIMIT 30',(alert['session_id'],alert['src'],aid))
        return render_template('alert_detail.html',page='alerts',title='Alert investigation',subtitle=alert['title'],alert=alert,related=related,others=others,session_row=session_row)

    @app.post('/alerts/<int:aid>')
    def alert_update(aid):
        if not store.one('SELECT id FROM alerts WHERE id=?',(aid,)):
            abort(404)
        status=request.form.get('status','')
        if status not in ('new','investigating','resolved','false_positive'):
            abort(400)
        store.execute('UPDATE alerts SET status=?,note=? WHERE id=?',(status,request.form.get('note','')[:3000],aid))
        store.audit('alert_updated',f'{aid}: {status}')
        flash('Investigation saved.','success')
        return redirect(url_for('alert_detail',aid=aid))

    @app.get('/hosts/<path:ip>')
    def host_detail(ip):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            abort(404)
        sid=selected()
        cond=' AND session_id=?' if sid else ''
        args=[ip,ip]+([sid] if sid else [])
        packets=store.rows('SELECT * FROM packets WHERE (src=? OR dst=?)'+cond+' ORDER BY id DESC LIMIT 100',args)
        alerts=store.rows('SELECT * FROM alerts WHERE (src=? OR dst=?)'+cond+' ORDER BY id DESC LIMIT 50',args)
        return render_template('host_detail.html',page='hosts',title='Host investigation',subtitle=ip,records=packets,alerts=alerts,ip=ip)

    @app.post('/rules')
    def save_rules():
        rules=store.config('rules')
        try:
            for key in rules:
                threshold=int(request.form.get(key+'_threshold','0'))
                window=int(request.form.get(key+'_window','0'))
                if not 1<=threshold<=100000000 or not 1<=window<=3600:
                    raise ValueError('Thresholds must be 1–100,000,000 and windows 1–3,600 seconds.')
                rules[key]={'enabled':request.form.get(key+'_enabled')=='on','threshold':threshold,'window':window}
            store.set_config('rules',rules)
            store.audit('rules_saved','Applies to new or restarted sessions')
            flash('Rules saved. Start a new session or restart a capture to apply them.','success')
        except ValueError as exc:
            flash(str(exc),'error')
        return redirect(url_for('rules'))

    @app.post('/settings')
    def save_settings():
        try:
            indicators=[str(ipaddress.ip_address(x.strip())) for x in request.form.get('indicators','').splitlines() if x.strip()]
            networks=[str(ipaddress.ip_network(x.strip(),strict=False)) for x in request.form.get('local_networks','').splitlines() if x.strip()]
            limit=int(request.form.get('max_packets','100000'))
            if not networks or len(indicators)>1000 or len(networks)>100 or not 1000<=limit<=500000:
                raise ValueError('Supply 1–100 local networks, up to 1,000 indicators, and a packet limit of 1,000–500,000.')
            store.set_config('settings',dict(indicators=indicators,local_networks=networks,max_packets=limit))
            store.audit('settings_saved')
            flash('Settings saved. Detection changes apply to new sessions.','success')
        except ValueError as exc:
            flash('Invalid settings: '+str(exc),'error')
        return redirect(url_for('settings'))

    @app.post('/account/email')
    def link_email():
        user=identities.one('SELECT * FROM users WHERE id=?',(session['uid'],))
        try:
            if user['email']:
                raise ValueError('This account already has its Gmail address linked.')
            if not check_password_hash(user['password'],request.form.get('password','')):
                raise ValueError('Your current password is incorrect.')
            email=canonical_gmail(request.form.get('email',''))
            identities.execute('UPDATE users SET email=? WHERE id=?',(email,user['id']))
            flash('Gmail address linked. You can now sign in with it.','success')
        except (ValueError,sqlite3.IntegrityError) as exc:
            flash('Unable to link Gmail. The address may already be registered.' if isinstance(exc,sqlite3.IntegrityError) else str(exc),'error')
        return redirect(url_for('settings'))

    @app.post('/settings/password')
    def password():
        user=identities.one('SELECT * FROM users WHERE id=?',(session['uid'],))
        new=request.form.get('new_password','')
        if not check_password_hash(user['password'],request.form.get('current_password','')) or not 12<=len(new)<=128:
            flash('Check your current password. New password must be 12–128 characters.','error')
        else:
            identities.execute('UPDATE users SET password=? WHERE id=?',(generate_password_hash(new),user['id']))
            store.audit('password_changed')
            flash('Password updated.','success')
        return redirect(url_for('settings'))

    @app.post('/sessions/<int:sid>/delete')
    def delete_session(sid):
        with engine.lock:
            if engine.active_id==sid and engine.worker and engine.worker.is_alive():
                flash('Stop this session before deleting it.','error')
            else:
                store.execute('DELETE FROM sessions WHERE id=?',(sid,))
                store.audit('session_deleted',str(sid))
                flash('Session and its retained traffic were deleted.','success')
        return redirect(url_for('settings'))

    @app.route('/team/<int:pid>/edit',methods=['GET','POST'])
    def profile_edit(pid):
        if identities.one('SELECT role FROM users WHERE id=?',(session['uid'],))['role']!='admin':
            abort(403,description='Only the administrator can edit the project developer profiles.')
        profile=identities.one('SELECT * FROM profiles WHERE id=?',(pid,))
        if not profile:
            abort(404)
        if request.method=='POST':
            values={key:request.form.get(key,'').strip()[:limit] for key,limit in [('name',80),('role',120),('bio',3000),('skills',500),('email',160),('github',300),('linkedin',300),('website',300)]}
            new_files=[]
            old_files=[]
            try:
                if not values['name']:
                    raise ValueError('A developer name is required.')
                for key in ['github','linkedin','website']:
                    if values[key] and (urlparse(values[key]).scheme not in ('http','https') or not urlparse(values[key]).netloc):
                        raise ValueError('Profile links must be full HTTP or HTTPS URLs.')
                if values['email'] and ('@' not in values['email'] or any(x in values['email'] for x in '\r\n')):
                    raise ValueError('Enter a valid email address.')
                for kind in ['photo','cv']:
                    field=request.files.get(kind)
                    if field and field.filename:
                        data=field.read(5*1024*1024+1)
                        if len(data)>5*1024*1024:
                            raise ValueError('Each photo or CV must be at most 5 MiB.')
                        name=secrets.token_hex(20)+('.png' if kind=='photo' else '.pdf')
                        target=root/'media'/name
                        if kind=='photo':
                            with Image.open(io.BytesIO(data)) as image:
                                if image.width*image.height>20000000:
                                    raise ValueError('Photo is too large. Use an image below 20 megapixels.')
                                image.thumbnail((1000,1000))
                                image.convert('RGB').save(target,'PNG')
                        else:
                            if not data.startswith(b'%PDF-') or b'%%EOF' not in data[-2048:]:
                                raise ValueError('CV must be a PDF file.')
                            target.write_bytes(data)
                        new_files.append(target)
                        if profile[kind]:
                            old_files.append(root/'media'/profile[kind])
                        profile[kind]=name
                identities.execute('UPDATE profiles SET name=?,role=?,bio=?,skills=?,email=?,github=?,linkedin=?,website=?,photo=?,cv=? WHERE id=?',
                    tuple(values[k] for k in ['name','role','bio','skills','email','github','linkedin','website'])+(profile['photo'],profile['cv'],pid))
                for target in old_files:
                    target.unlink(missing_ok=True)
                store.audit('profile_updated',f'Developer {pid}')
                flash('Developer profile updated.','success')
                return redirect(url_for('team'))
            except (ValueError,UnidentifiedImageError,Image.DecompressionBombError,OSError) as exc:
                for target in new_files:
                    target.unlink(missing_ok=True)
                flash('Profile could not be saved: '+str(exc),'error')
        return render_template('profile_edit.html',page='team',title='Edit developer',subtitle='Make this project yours.',profile=profile)

    @app.get('/media/<name>')
    def media(name):
        if not identities.one('SELECT id FROM profiles WHERE photo=? OR cv=?',(name,name)):
            abort(404)
        target=root/'media'/name
        if not target.is_file():
            abort(404)
        return send_file(target,as_attachment=name.endswith('.pdf'),download_name='developer-cv.pdf' if name.endswith('.pdf') else name)

    @app.get('/export/<kind>')
    def export(kind):
        sid=selected()
        if kind=='summary':
            report=summary(sid)
            report['generated_utc']=datetime.now(timezone.utc).isoformat()
            report['interpretation']='Behavioral indicators, not proof of compromise. Synthetic sessions are explicitly labeled demo.'
            return Response(json.dumps(report,indent=2),mimetype='application/json',headers={'Content-Disposition':'attachment; filename=sentinelflow-report.json'})
        if kind not in ('alerts','packets'):
            abort(404)
        w,args=where(sid)
        rows=store.rows('SELECT * FROM '+kind+w+' ORDER BY id DESC LIMIT 100000',args)
        output=io.StringIO(newline='')
        writer=csv.writer(output)
        fields=['id','session_id','ts','src','dst','sport','dport','proto','length','flags','dns'] if kind=='packets' else ['id','session_id','ts','rule','severity','src','dst','title','evidence','status','note']
        writer.writerow(fields)
        for row in rows:
            # Defuse spreadsheet formulas in user-supplied notes and captured DNS labels.
            writer.writerow([("'"+str(row[k])) if str(row[k]).lstrip().startswith(('=','+','-','@','\t','\r')) else row[k] for k in fields])
        return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename=sentinelflow-{kind}.csv'})

    return app
