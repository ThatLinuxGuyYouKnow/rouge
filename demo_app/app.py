import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)

conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
conn.execute("INSERT INTO users VALUES (1, 'admin', 'supersecret', 'admin')")
conn.execute("INSERT INTO users VALUES (2, 'alice', 'password123', 'user')")
conn.execute("INSERT INTO users VALUES (3, 'bob', 'qwerty', 'user')")
conn.commit()

os.makedirs("./files", exist_ok=True)
with open("./files/hello.txt", "w") as f:
    f.write("Hello, world!")
with open("./files/config.ini", "w") as f:
    f.write("[database]\nhost=localhost\npassword=dbpass123\n")


def search_user(username: str) -> list:
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()


def ping_host(host: str) -> str:
    return os.popen(f"ping -c 1 {host}").read()


def greet(name: str) -> str:
    return f"<h1>Hello, {name}!</h1>"


def read_file(filename: str) -> str:
    with open(f"./files/{filename}") as f:
        return f.read()


@app.route("/search")
def search():
    user = request.args.get("user", "")
    return str(search_user(user))


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    return ping_host(host)


@app.route("/greet")
def greet_route():
    name = request.args.get("name", "")
    return greet(name)


@app.route("/read")
def read_route():
    filename = request.args.get("file", "")
    return read_file(filename)


if __name__ == "__main__":
    app.run(port=5000)
