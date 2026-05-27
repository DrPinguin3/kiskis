import pathlib
import typing
import html
import hashlib
import base64
from . import totp

from flask import Flask, redirect, request, url_for, session

from kiskis import storage


def get_auth_hash(password: str) -> str:
    """Erzeugt einen Hash des Master-Passworts für die Authentifizierung."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()).decode()


def get_storage_path():
    return pathlib.Path.home() / ".kiskis_storage"


def get_auth_path():
    return pathlib.Path.home() / ".kiskis_auth"


def save_master_password(password: str):
    """Speichert den Hash des Master-Passworts zur späteren Prüfung."""
    auth_path = get_auth_path()
    with open(auth_path, "w") as f:
        f.write(get_auth_hash(password))


def verify_master_password(password: str) -> bool:
    """Prüft ob das eingegebene Passwort mit dem gespeicherten Hash übereinstimmt."""
    auth_path = get_auth_path()
    if not auth_path.exists():
        return False
    with open(auth_path) as f:
        stored_hash = f.read().strip()
    return get_auth_hash(password) == stored_hash


def create_app():
    app = Flask(__name__)
    app.secret_key = "change-this-secret-key-in-production"

    @app.route("/login", methods=["GET", "POST"])
    def login():
        auth_path = get_auth_path()
        
        if request.method == "POST":
            password = request.values.get("password", "")
            
            if not auth_path.exists():
                save_master_password(password)
                session["master_password"] = password
                session["authenticated"] = True
                return redirect("/passwords/")
            elif verify_master_password(password):
                session["master_password"] = password
                session["authenticated"] = True
                return redirect("/passwords/")
            else:
                return f"""
                    <p style="color: red;">Wrong password!</p>
                    <form action="{url_for("login")}" method="post">
                        Master Password: <input type="password" name="password"><br/>
                        <input type="submit" value="Login">
                    </form>"""
        
        return f"""
            <form action="{url_for("login")}" method="post">
                Master Password: <input type="password" name="password"><br/>
                <input type="submit" value="Login">
            </form>"""

    @app.before_request
    def require_auth():
        if not session.get("authenticated"):
            excluded_routes = ["/login", "/static"]
            if not any(request.path.startswith(route) for route in excluded_routes):
                return redirect("/login")

    def get_storage():
        master_password = session.get("master_password")
        return storage.Storage(get_storage_path(), master_password)

    @app.route("/")
    def default_route():
        return redirect("/passwords/")

    @app.route("/passwords/")
    def passwords():
        storage_ = get_storage()
        secrets: typing.Dict = storage_.data
        response = "<ul>" + "".join(
            [
                f"<li>Username: {html.escape(item['username'])}. Purpose: {html.escape(item['purpose'])}. Password: {html.escape(item['password'])}. TOTP Secret: {html.escape(item['totp_secret'])}."
                + f"TOTP Token: {html.escape(totp.totp(item['totp_secret']))}."
                + f'<a href="{html.escape(url_for("delete", username=item["username"]))}">Delete.</a></li>'
                for item in secrets["passwords"]
            ]
        )

        response += f'<p><a href="{html.escape(url_for("prepare"))}">Add</a></p>'
        return response

    @app.route("/passwords/prepare")
    def prepare():
        return f"""
            <form action="{html.escape(url_for("add"))}" method="post">
                Username: <input type="text" name="username"><br/>
                Purpose: <input type="text" name="purpose"><br/>
                Password: <input type="text" name="password"><br/>
                TOTP Secret: <input type="text" name="totp_secret"><br/>
                <input type="submit" value="Add">
            </form>"""

    @app.route("/passwords/add", methods=["POST"])
    def add():
        storage_ = get_storage()
        record = {
            "username": request.values.get("username", ""),
            "purpose": request.values.get("purpose", ""),
            "password": request.values.get("password", ""),
            "totp_secret": request.values.get("totp_secret", ""),
        }
        storage_.data["passwords"].append(record)
        storage_.save()
        return redirect("/passwords")

    @app.route("/passwords/<username>/delete")
    def delete(username: str):
        storage_ = get_storage()
        record = next(
            (item for item in storage_.data["passwords"] if item["username"] == username),
            None,
        )
        if record:
            storage_.data["passwords"].remove(record)
            storage_.save()
        return redirect("/passwords")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    return app


def main():
    app = create_app()
    app.run(debug=True)


if __name__ == "__main__":
    main()
