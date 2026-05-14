import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, request


app = Flask(__name__)
DB_PATH = "/tmp/makina-demo.db"
ADMIN_TOKEN = "demo-admin-token"


def db():
    return sqlite3.connect(DB_PATH)


@app.get("/user")
def get_user():
    name = request.args.get("name", "")
    query = f"SELECT id, name, role FROM users WHERE name = '{name}'"
    rows = db().cursor().execute(query).fetchall()
    return {"rows": rows}


@app.post("/reset")
def reset_password():
    token = request.headers.get("x-admin-token", "")
    if token != ADMIN_TOKEN:
        return {"ok": False}, 403

    user_id = request.form.get("user_id", "")
    password = request.form.get("password", "")
    sql = f"UPDATE users SET password = '{password}' WHERE id = {user_id}"
    db().cursor().execute(sql)
    return {"ok": True}


@app.post("/image")
def resize_image():
    filename = request.form.get("filename", "")
    width = request.form.get("width", "200")
    command = f"convert {filename} -resize {width}x /tmp/output.png"
    os.system(command)
    return {"output": "/tmp/output.png"}


@app.post("/ping")
def ping_host():
    host = request.form.get("host", "")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True).decode()


@app.post("/session")
def restore_session():
    payload = request.get_data()
    session = pickle.loads(payload)
    return {"user": session.get("user")}


@app.post("/calculate")
def calculate():
    expression = request.form.get("expression", "0")
    return {"result": eval(expression)}


@app.get("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    return requests.get(url, timeout=5).text


@app.post("/token")
def token():
    password = request.form.get("password", "")
    return {"token": hashlib.md5(password.encode()).hexdigest()}
