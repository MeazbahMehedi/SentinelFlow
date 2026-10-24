"""One-process local launcher with cooperative, quiet Ctrl+C shutdown."""
import os
import signal
from contextlib import suppress
from sentinelflow import create_app


def main():
    from waitress import create_server
    from waitress import wasyncore
    app=create_app()
    stopping=app.extensions['stopping']
    server=create_server(app,host=os.getenv('HOST','127.0.0.1'),port=int(os.getenv('PORT','5000')),threads=24,channel_timeout=120,
                         asyncore_loop_timeout=.2)
    def request_stop(signum=None,frame=None):
        if not stopping.is_set():
            print('\nStopping SentinelFlow. Finishing capture and closing connections...',flush=True)
        stopping.set()
    stop_signals=[signal.SIGINT,signal.SIGTERM]
    if hasattr(signal,'SIGBREAK'):
        stop_signals.append(signal.SIGBREAK)
    for sig in stop_signals:
        signal.signal(sig,request_stop)
    print(f"SentinelFlow is ready at http://127.0.0.1:{os.getenv('PORT','5000')}",flush=True)
    print('Create an account or sign in in your browser. Press Ctrl+C once to stop.',flush=True)
    try:
        # One bounded Waitress event-loop iteration at a time. Custom signal handlers
        # set a flag instead of raising inside Waitress's own shutdown waits.
        while not stopping.is_set():
            server.asyncore.loop(timeout=.2,count=1,map=server._map,use_poll=server.adj.asyncore_use_poll)
    except KeyboardInterrupt:
        request_stop()
    finally:
        stopping.set()
        with suppress(KeyboardInterrupt):
            app.extensions['shutdown']()
            server.task_dispatcher.shutdown(timeout=4)
            server.close()
            wasyncore.close_all(server._map,ignore_all=True)
        # Keep cooperative handlers during atexit cleanup: a second Ctrl+C must
        # not raise KeyboardInterrupt while the interpreter closes worker threads.
        print('SentinelFlow stopped cleanly.',flush=True)
    return 0

if __name__=='__main__':
    raise SystemExit(main())
