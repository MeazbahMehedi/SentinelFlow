"""Optional browser smoke check of the actual Waitress launcher.
Install requirements-dev.txt and run `python -m playwright install chromium` first.
Uses an isolated temporary workspace and never modifies normal runtime data.
"""
from pathlib import Path
import os
import socket
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from playwright.sync_api import sync_playwright,expect

ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='sentinelflow-browser-') as tmp:
    # Ask the OS for an unused local port for this isolated check.
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    env=dict(os.environ,SENTINELFLOW_DATA=tmp,PORT=str(port))
    base=f'http://127.0.0.1:{port}'
    with open(Path(tmp)/'server.log','w') as log:
        process=subprocess.Popen([sys.executable,'-u','run.py'],cwd=ROOT,env=env,stdout=log,stderr=log,creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name=='nt' else 0)
        try:
            for _ in range(80):
                try:
                    urllib.request.urlopen(base,timeout=.5).close();break
                except Exception:
                    if process.poll() is not None:raise RuntimeError('Launcher exited unexpectedly.')
                    time.sleep(.1)
            else:raise RuntimeError('Launcher did not become ready.')
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True,args=['--no-sandbox'])
                page=browser.new_page(viewport={'width':1440,'height':1000})
                errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
                page.goto(base,wait_until='domcontentloaded')
                page.locator('[name=email]').fill('browser.reviewer@gmail.com')
                page.locator('[name=username]').fill('browser-reviewer')
                page.locator('[name=password]').fill('BrowserReviewPassword123')
                page.get_by_role('button',name='Create workspace').click()
                page.get_by_role('button',name='Load guided demo').click()
                page.get_by_role('combobox',name='Replay speed').select_option('32')
                page.get_by_role('button',name='Start replay',exact=True).click()
                page.wait_for_timeout(2500)
                for key in ['','traffic','alerts','replay','hosts','analytics','rules','team','repositories','settings']:
                    response=page.goto(base+'/'+key,wait_until='domcontentloaded')
                    page.wait_for_timeout(160)
                    assert response.status==200,(key,response.status)
                    assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'),key
                snapshot=page.request.get(base+'/api/snapshot').json()
                assert snapshot['totals']['packets']==501
                assert snapshot['totals']['alerts']==6
                page.goto(base+'/alerts/1',wait_until='domcontentloaded')
                page.locator('[name=status]').select_option('investigating')
                page.locator('[name=note]').fill('Browser verification note')
                page.get_by_role('button',name='Save investigation').click()
                assert page.locator('[name=note]').input_value()=='Browser verification note'
                page.goto(base+'/team/1/edit',wait_until='domcontentloaded')
                page.locator('[name=name]').fill('Developer one')
                page.locator('[name=role]').fill('Detection engineer')
                page.get_by_role('button',name='Save developer profile').click()
                expect(page.get_by_role('heading',name='Developer one',exact=True)).to_be_visible()
                screenshot_dir=os.environ.get('SENTINELFLOW_QA_SCREENSHOTS')
                for theme in ['dark','light']:
                    page.evaluate("theme=>{localStorage.setItem('sentinelflow-theme',theme);}",theme)
                    for width,height in [(1440,1000),(390,844)]:
                        page.set_viewport_size({'width':width,'height':height})
                        for key in ['','traffic','alerts','replay','hosts','analytics','rules','team','repositories','settings']:
                            page.goto(base+'/'+key,wait_until='domcontentloaded');page.wait_for_timeout(140)
                            assert page.locator('html').get_attribute('data-theme')==theme
                            assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'),(theme,width,key)
                            if screenshot_dir and key in ['','repositories','replay','team','settings']:
                                directory=Path(screenshot_dir);directory.mkdir(parents=True,exist_ok=True)
                                page.wait_for_timeout(500)
                                page.screenshot(path=str(directory/f"{theme}-{width}-{key or 'overview'}.png"),full_page=True)
                # Appearance is changed by a real control and survives navigation.
                page.locator('[data-theme-toggle]').click()
                assert page.locator('html').get_attribute('data-theme')=='dark'
                page.reload(wait_until='domcontentloaded')
                assert page.locator('html').get_attribute('data-theme')=='dark'
                page.get_by_role('button',name='Toggle navigation').click()
                assert page.locator('#sidebar').evaluate("el=>el.classList.contains('open')")
                # A second browser account cannot see the first account's capture data.
                context2=browser.new_context(viewport={'width':1200,'height':900})
                second=context2.new_page();second.on('pageerror',lambda e:errors.append(str(e)))
                second.goto(base+'/login',wait_until='domcontentloaded')
                second.get_by_role('link',name='Create your account').click()
                second.locator('[name=email]').fill('browserreviewer+duplicate@gmail.com')
                second.locator('[name=username]').fill('second')
                second.locator('[name=password]').fill('SecondBrowserPassword123')
                second.get_by_role('button',name='Create account',exact=True).click()
                expect(second.get_by_text('This Gmail address already has an account. Sign in instead.',exact=True)).to_be_visible()
                second.locator('[name=email]').fill('second-browser@gmail.com')
                # Use a valid consumer Gmail local name in the test.
                second.locator('[name=email]').fill('secondbrowser@gmail.com')
                second.locator('[name=password]').fill('SecondBrowserPassword123')
                second.get_by_role('button',name='Create account',exact=True).click()
                expect(second.get_by_role('heading',name='Overview',exact=True)).to_be_visible()
                assert second.request.get(base+'/api/snapshot').json()['sessions']==[]
                assert second.request.get(base+'/alerts/1').status==404
                assert second.request.get(base+'/team/1/edit').status==403
                context2.close()
                # Keep a replay and browser SSE connection active while testing repeated Ctrl+C.
                page.goto(base+'/replay',wait_until='domcontentloaded')
                page.get_by_role('button',name='Load guided demo').click()
                page.get_by_role('combobox',name='Replay speed').first.select_option('0.25')
                page.get_by_role('button',name='Start replay',exact=True).click()
                expect(page.get_by_role('button',name='Pause',exact=True)).to_be_visible()
                page.get_by_role('button',name='Pause',exact=True).click()
                page.wait_for_timeout(300)
                process.send_signal(signal.CTRL_BREAK_EVENT if os.name=='nt' else signal.SIGINT)
                time.sleep(.08)
                if os.name!='nt' and process.poll() is None:process.send_signal(signal.SIGINT)
                process.wait(timeout=12)
                log.flush();output=(Path(tmp)/'server.log').read_text()
                assert process.returncode==0,(process.returncode,output)
                assert 'Traceback' not in output,output
                assert 'stopped cleanly' in output,output
                assert not errors,errors
                browser.close()
                print('PASS: actual launcher, account isolation, Gmail uniqueness, 501-packet replay and six alerts, 10 pages in both themes at desktop/mobile sizes, triage, profiles, theme persistence, mobile menu, and repeated Ctrl+C with an active replay/SSE connection.')
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
