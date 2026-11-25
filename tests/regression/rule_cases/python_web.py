# Annotated cases for vtest/rules/python-web.yml (checked by test_rules.py).
# "# ruleid: <id>" means the next line must be flagged by that rule; "# ok: <id>" means it must not.
import base64
import hashlib
import html
import os
import pathlib
import pickle
import random
import secrets
import subprocess
import urllib.parse

import elementpath
import yaml
from flask import Flask, make_response, redirect, request, session
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)


@app.route("/file")
def read_file():
    name = request.args.get("name", "")
    # ruleid: vtest-path-traversal
    with open(f"/srv/files/{name}") as fh:
        data = fh.read()
    # ok: vtest-path-traversal
    with open(f"/srv/files/{os.path.basename(name)}") as fh:
        data += fh.read()
    return html.escape(data)


@app.route("/file-checked")
def read_checked():
    base = pathlib.Path("/srv/files")
    path = (base / request.args.get("name", "")).resolve()
    if not str(path).startswith(str(base)):
        return "invalid path"
    # ok: vtest-path-traversal
    with open(path) as fh:
        return html.escape(fh.read())


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    page = f"<h1>Hello {name}</h1>"
    # ruleid: vtest-flask-xss
    return page


@app.route("/hello-escaped")
def hello_escaped():
    name = request.args.get("name", "")
    # ok: vtest-flask-xss
    return f"<h1>Hello {html.escape(name)}</h1>"


@app.route("/header")
def header_only():
    name = request.args.get("name", "")
    # ok: vtest-flask-xss
    return make_response(("ok", {"X-Name": name}))


@app.route("/go")
def go():
    target = request.args.get("next", "/")
    # ruleid: vtest-open-redirect
    return redirect(target)


@app.route("/go-checked")
def go_checked():
    target = request.args.get("next", "/")
    url = urllib.parse.urlparse(target)
    if url.netloc not in ("example.com",) or url.scheme != "https":
        return "invalid url"
    # ok: vtest-open-redirect
    return redirect(target)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # ruleid: vtest-command-injection
    first = subprocess.run(f"ping -c1 {host}", shell=True, capture_output=True)
    # ok: vtest-command-injection
    second = subprocess.run(["ping", "-c1", host], capture_output=True)
    return str(first.returncode + second.returncode)


@app.route("/user")
def user(cur):
    uid = request.args.get("id", "")
    # ruleid: vtest-sql-injection
    cur.execute(f"SELECT * FROM users WHERE id = '{uid}'")
    # ok: vtest-sql-injection
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return "ok"


@app.route("/ldap")
def ldap_lookup(conn):
    name = request.args.get("name", "")
    # ruleid: vtest-ldap-injection
    conn.search("ou=users", f"(uid={name})")
    # ok: vtest-ldap-injection
    conn.search("ou=users", f"(uid={escape_filter_chars(name)})")
    return "ok"


@app.route("/xpath")
def xpath_lookup(root):
    name = request.args.get("name", "")
    # ruleid: vtest-xpath-injection
    first = elementpath.select(root, f"//user[@name='{name}']")
    # ok: vtest-xpath-injection
    second = root.xpath("//user[@name=$n]", n=name)
    return str(len(first) + len(second))


@app.route("/remember")
def remember():
    # ruleid: vtest-trust-boundary
    session["user"] = request.args.get("user")
    # ok: vtest-trust-boundary
    session["visits"] = int(request.args.get("visits", "0"))
    return "ok"


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    # ruleid: vtest-code-injection
    return str(eval(expr))


@app.route("/calc-literal")
def calc_literal():
    expr = request.args.get("expr", "")
    if not expr.startswith("'") or not expr.endswith("'"):
        return "only string literals"
    # ok: vtest-code-injection
    return str(eval(expr))


@app.route("/load")
def load():
    data = base64.b64decode(request.args.get("d", ""))
    # ruleid: vtest-unsafe-deserialization
    obj = pickle.loads(data)
    # ruleid: vtest-unsafe-deserialization
    cfg = yaml.load(data, Loader=yaml.Loader)
    # ok: vtest-unsafe-deserialization
    safe = yaml.load(data, Loader=yaml.SafeLoader)
    return str((obj, cfg, safe))


@app.route("/login")
def login():
    resp = make_response("ok")
    # ruleid: vtest-weak-random-secret
    session_token = str(random.random())[2:]
    # ruleid: vtest-weak-random-secret
    resp.set_cookie("remember", str(random.getrandbits(64)))
    # ok: vtest-weak-random-secret
    resp.set_cookie("theme", secrets.token_hex(8))
    # ok: vtest-weak-random-secret
    retry_delay = random.uniform(0.1, 0.5)
    # ok: vtest-weak-random-secret
    random.shuffle([1, 2, 3])
    # ruleid: vtest-cookie-not-secure
    resp.set_cookie("sid", session_token, secure=False)
    # ok: vtest-cookie-not-secure
    resp.set_cookie("sid", session_token, secure=True, httponly=True)
    return resp if retry_delay else resp


def checksum(data: bytes) -> str:
    # ruleid: vtest-weak-hash-by-name
    weak = hashlib.new("md5", data).hexdigest()
    # ok: vtest-weak-hash-by-name
    strong = hashlib.new("sha256", data).hexdigest()
    return weak + strong
