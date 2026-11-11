"""JSON endpoints used by the dashboard scripts."""

from __future__ import annotations

import json

from flask import Blueprint, Response, abort, jsonify, request, stream_with_context

from .. import analytics, capture
from ..github import DEVELOPERS
from .helpers import require_admin, selected_session, services, store

bp = Blueprint("api", __name__, url_prefix="/api")

STREAM_SECONDS = 30
HEARTBEAT_SECONDS = 10


@bp.get("/snapshot")
def snapshot():
    """Dashboard summary. ``?rev=N`` returns 204 when nothing changed since revision N."""
    sid = selected_session()
    workspace = store()
    if request.args.get("rev") == str(workspace.revision):
        return Response(status=204)
    return jsonify(analytics.summary(workspace, sid))


@bp.get("/packets")
def packet_feed():
    w, args = analytics.scope(selected_session())
    return jsonify(store().rows("SELECT * FROM packets" + w + " ORDER BY id DESC LIMIT 50", args))


@bp.get("/graph")
def host_graph():
    return jsonify(analytics.graph(store(), selected_session()))


@bp.get("/stream")
def stream():
    """Server-sent events for external consumers.

    The bundled dashboard polls ``/api/snapshot`` instead, because each open
    stream occupies a server thread. Streams are short and only send data when
    the workspace changes, with a comment heartbeat in between.
    """
    sid = selected_session()
    workspace = store()
    stopping = services().stopping

    @stream_with_context
    def events():
        last_revision = None
        quiet = 0
        for _ in range(STREAM_SECONDS):
            if stopping.is_set():
                break
            if workspace.revision != last_revision:
                last_revision = workspace.revision
                quiet = 0
                yield "data: " + json.dumps(analytics.summary(workspace, sid)) + "\n\n"
            else:
                quiet += 1
                if quiet >= HEARTBEAT_SECONDS:
                    quiet = 0
                    yield ": keep-alive\n\n"
            if stopping.wait(1):
                break

    return Response(events(), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})


@bp.get("/github/<login>")
def github_repositories(login: str):
    if login not in DEVELOPERS:
        abort(404)
    return jsonify(services().github.repositories(login))


@bp.get("/capture/status")
def capture_status():
    require_admin()
    return jsonify(capture.capture_diagnostics(refresh=True))
