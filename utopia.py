import lxml.html
from lxml.html import builder as E
from mitmproxy import http

import fnmatch
import json
import logging
import re
import string
import traceback
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


def recurse_json(data, replace_data):
    if isinstance(data, list):
        changed = []
        for x in data:
            changed.append(recurse_json(x), replace_data)
        return changed
    elif isinstance(data, dict):
        changed = {}
        for key, val in data.items():
            changed[key] = recurse_json(val, replace_data)
    elif isinstance(data, str):
        return replace_data.get(data, data)
    else:
        return data


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
        to_replace.update(data.get("replace_hosts", {}).get(flow.request.host, {}))

        txt = flow.response.text

        if is_html:
            try:
                tree = lxml.html.fromstring(txt)

                for elem in tree.xpath(".//meta"):
                    if elem.get("http-equiv"):
                        elem.getparent().remove(elem)

                for elem in tree.xpath(".//body"):
                    js_content = open("bait.js", "r").read()
                    injector = E.SCRIPT(js_content)
                    elem.getparent().insert(0, injector)
                    break

                txt = lxml.html.tostring(tree).decode()

            except:
                print("XML parser error in " + flow.request.url)
                traceback.print_exc()

        for key, value in to_replace.items():
            value = string.Template(value).safe_substitute(data.get("identity", {}))
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

    flow.request.marker = ":mage_man:"

    redir_host = data.get("redirect_hosts", {}).get(host)
    if redir_host:
        flow.request.host = redir_host

    for pattern, dest in data.get("path_replace_hosts", {}).items():
        match = re.match(pattern, str(flow.request.url))
        if match is None:
            continue

        groups = {}

        for idx, group in enumerate(match.groups()):
            groups[f"regex{idx}"] = group

        flow.request.url = string.Template(dest).safe_substitute(groups)
        logger.info("Rewriting url to: " + flow.request.url)
        break

    if flow.request.url.endswith(".js"):
        return
