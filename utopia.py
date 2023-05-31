import xml.etree.ElementTree as ET
from mitmproxy import http

import fnmatch
import json
import logging
from pathlib import Path


data = {}
data_stats = None
cdir = Path(__file__).parent
data_path = cdir / "data.json"
logger = logging.getLogger(__name__)


def load_data():
    global data, data_stats

    current_stats = data_path.stat()

    if data_stats is not None and (current_stats.st_mtime == data_stats.st_mtime and current_stats.st_size == data_stats.st_size):
        return

    try:
        data = json.loads(data_path.read_text())
        data_stats = current_stats
    except json.JSONDecodeError:
        logger.warning("Chyba dekodovania dat")


url_replace = {
}



def response(flow: http.HTTPFlow) -> None:
    if flow.response:
        flow.response.headers.update(data.get("add_headers", {}).copy())

        for header in tuple(flow.response.headers.keys()):
            if header.lower() in data.get("remove_headers", []):
                del flow.response.headers[header]

        for pattern, target in data.get("redirects", {}).items():
            if fnmatch.fnmatch(flow.request.url, pattern):
                flow.response.status_code = 302
                flow.response.headers["Location"] = target
                return

        for x in data.get("intercepted_hosts", []):
            if flow.request.pretty_host.endswith(x):
                break
        else:
            return

        if flow.request.pretty_host.startswith("api"):
            return

        is_html = False
        is_js = False

        for k, v in flow.response.headers.items():
            if "text/html" in v.lower():
                is_html = True
                break
            elif "application/javascript" in v.lower():
                is_js = True
                break

        if not (is_html or is_js):
            return

        to_replace = data.get("replace_global", {})
        txt = flow.response.text

        if is_html:
            to_replace.update(data.get("replace_hosts", {}).get(flow.request.host, {}))

        for key, value in to_replace.items():
            txt = txt.replace(key, value)

        flow.response.text = txt
        logger.info(f"intercepting html `{flow.request.url}`")


def request(flow: http.HTTPFlow) -> None:
    load_data()
    host = flow.request.pretty_host

    # Automatically add and respond to CORS
    if flow.request.method == "OPTIONS":
        flow.response = http.Response.make(200, b"",
           {
               "Access-Control-Allow-Origin": "*",
               "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE",
               "Access-Control-Allow-Headers": "*",
               "Access-Control-Max-Age": "1728000"
           })
        return

    for x in data.get("intercepted_hosts", []):
        if host.endswith(x):
            break
    else:
        return

    if flow.websocket:
        return

    redir_host = data.get("redirect_hosts", {}).get(host)
    if redir_host:
        flow.request.host = redir_host

    if host == "mojatatrabanka.sk":
        flow.request.host = ""
        if flow.request.path == "/html-tb/":
            flow.request.path = "/html-tb/demo/"

    # TODO: make configurable
    if flow.request.path.startswith("/mbc"):
        flow.request.path = "/cs/demo" + flow.request.path

    for k, v in url_replace.items():
        if k in flow.request.url:
            flow.request.url = flow.request.url.replace(k, v)

    if flow.request.url.endswith(".js"):
        return
