import xml.etree.ElementTree as ET
from mitmproxy import http

import fnmatch

global_replace = {
    "This is a test network. Coins have no value": "System is currently under the maintenance",
    "3MwWabrzoL2Z8mK9LnUpT5KjMLBYRPQUuW": "3MwWabrzoL2Z8mK9LnUpT5KjMLBYRPSCAM",
    "0xA7A177EB6D09Ced0ADcDe14dc99153167b027C38": "0xA7A177EB6D09Ced0ADcDe14dc99153167b02SCAM"
}


content_replace = {
    "Phemex testnet: Crypto Simulation Trading": "Phemex trading",
    "Testnet Markets": "Mainnet Markets",
    #"testnet.phemex.com": "mainnet.phemex.com",
    #"/login?": "https://mainnet.phemex.com/login",
    #"Withdraw": "",
    "Register on Testnet now to claim testing bonus": "Register for VIP account to get free rectal probing",
    "Ready to Trade Live": "Help",
    "Simulation": "Super real legit"
}


paths = {
    "/assets/withdrawal": False
}


url_replace = {
    "testnet-logo-light.svg": "logo-light-v2.svg",
    "testnet-logo-dark.svg": "logo-light-v2.svg",
}



testnet_urls = (
    #"*/login.72.js",
    #"*/client/*/main.js",
    #"*$lang_account_api*",
    "*c8211af429f90310706e*"
)


def response(flow: http.HTTPFlow) -> None:
    if flow.response:
        for k, v in global_replace.items():
            flow.response.text = flow.response.text.replace(k, v)

        if flow.request.url.endswith(".js"):
            return
        elif flow.request.pretty_host.startswith("api"):
            return

        is_html = False

        for k, v in flow.response.headers.items():
            if "text/html" in v.lower():
                is_html = True

        if is_html:
            txt = flow.response.text

            for key, value in content_replace.items():
                txt = txt.replace(key, value)

            flow.response.text = txt
            print(f"intercepting html `{flow.request.url}`")


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host

    for k, v in flow.request.headers.items():
        if k.lower() == "host":
            continue
        elif "mainnet" in v:
            flow.request.headers[k] = v.replace("mainnet", "testnet")

    if host == "phemex.com" or host == "mainnet.phemex.com":
        for x in testnet_urls:
            if fnmatch.fnmatch(flow.request.url, x):
                flow.request.host = "testnet.phemex.com"
    elif host == "api10-mainnet.phemex.com":
        flow.request.host = "testnet.phemex.com"
        flow.request.path = "/api" + flow.request.path
        print("Replaced: " + flow.request.url)
        return

    if flow.request.path.startswith("/assets/withdrawal"):
        flow.response = http.Response.make(500, b"Temporary server error, try again later", {})

    for k, v in url_replace.items():
        if k in flow.request.url:
            flow.request.url = flow.request.url.replace(k, v)

    if "mainnet" in flow.request.host:
        flow.request.host = flow.request.host.replace("mainnet", "testnet")
