import os, subprocess, zipfile
from flask import Flask, request, send_file, render_template_string, abort

app = Flask(__name__)
BASE = "/srv/files"

@app.route("/download")
def download():
    name = request.args.get("name")
    path = os.path.join(BASE, name)
    return send_file(path)

@app.route("/safe")
def safe_download():
    name = request.args.get("name")
    path = os.path.realpath(os.path.join(BASE, name))
    if not path.startswith(BASE):
        abort(403)
    return send_file(path)

@app.route("/ping")
def ping():
    host = request.form["host"]
    return subprocess.check_output("ping -c 1 " + host, shell=True)

@app.route("/hello")
def hello():
    who = request.args.get("who", "")
    return render_template_string(f"<h1>Hello {who}</h1>")

@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))

def unzip(archive, dest):
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            out = os.path.join(dest, info.filename)
            with open(out, "wb") as f:
                f.write(z.read(info))
