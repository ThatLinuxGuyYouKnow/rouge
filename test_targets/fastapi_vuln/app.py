import os
import sqlite3
import subprocess
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

app = FastAPI()

DATABASE_PASSWORD = "admin123!"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.execute("INSERT INTO users VALUES (1, 'root', 'toor')")
conn.execute("INSERT INTO users VALUES (2, 'alice', 'wonderland')")
conn.commit()


def lookup_user(username: str) -> list:
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()


def create_user(username: str, password: str) -> str:
    query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
    conn.execute(query)
    conn.commit()
    return f"Created {username}"


def run_backup(hostname: str) -> str:
    cmd = f"pg_dump -h {hostname} -U admin mydb"
    return os.popen(cmd).read()


def shell_cmd(command: str) -> str:
    return subprocess.getoutput(command)


def welcome(name: str) -> str:
    return f"<h1>Welcome back, {name}!</h1>"


def log_visit(page: str) -> str:
    js = f"<script>console.log('User visited {page}')</script>"
    return f"<html><body>{js}</body></html>"


def read_doc(filename: str) -> str:
    with open(f"./docs/{filename}") as f:
        return f.read()


def fetch_avatar(url: str) -> bytes:
    import urllib.request
    return urllib.request.urlopen(url).read()


@app.get("/search")
def search(user: str = Query("")):
    return {"results": lookup_user(user)}


@app.get("/register")
def register(username: str = Query(""), password: str = Query("")):
    return {"status": create_user(username, password)}


@app.get("/backup")
def backup(host: str = Query("localhost")):
    return {"output": run_backup(host)}


@app.get("/exec")
def exec_cmd(cmd: str = Query("")):
    return {"output": shell_cmd(cmd)}


@app.get("/greet")
def greet(name: str = Query("world")):
    return HTMLResponse(welcome(name))


@app.get("/log")
def log(page: str = Query("/")):
    return HTMLResponse(log_visit(page))


@app.get("/docs/read")
def docs(filename: str = Query("index.txt")):
    return {"content": read_doc(filename)}


@app.get("/avatar")
def avatar(url: str = Query("")):
    data = fetch_avatar(url)
    return {"size": len(data)}


@app.get("/health")
def health():
    return {"ok": True}
