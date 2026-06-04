import pathlib
import base64
import hashlib
import copy

import yaml
from cryptography.fernet import Fernet


def get_key_from_password(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


class Storage:
    def __init__(self, storage_path: pathlib.Path, master_password: str = None):
        self.master_password = master_password
        self.key = get_key_from_password(self.master_password) if self.master_password else None
        self.storage_path = storage_path
        self.data = {
            "passwords": [
                {
                    "username": "president_skroob",
                    "purpose": "luggage",
                    "password": "12345"
                },
                {"username": "admin", "purpose": "admin", "password": "admin"},
                {"username": "AzureDiamond", "purpose": "IRC", "password": "hunter2"},
            ]
        }

        if self.storage_path.exists():
            with open(storage_path) as storage_file:
                file_data = yaml.load(storage_file, Loader=yaml.Loader)
            if self.key:
                self.data = self._decrypt_data(file_data)
            else:
                self.data = file_data
        else:
            self.save()

    def _encrypt_value(self, value: str) -> str:
        if not self.key:
            return value
        f = Fernet(self.key)
        encrypted = f.encrypt(value.encode())
        return base64.b64encode(encrypted).decode()

    def _decrypt_value(self, value: str) -> str:
        if not self.key:
            return value
        f = Fernet(self.key)
        try:
            encrypted = base64.b64decode(value.encode())
            decrypted = f.decrypt(encrypted)
            return decrypted.decode()
        except Exception:
            return value

    def _encrypt_data(self, data: dict) -> dict:
        encrypted = {"passwords": []}
        for item in data.get("passwords", []):
            encrypted_item = copy.deepcopy(item)

            if "password" in item.keys():
                encrypted_item["password"] = self._encrypt_value(item["password"])
            if "totp_secret" in item.keys():
                encrypted_item["totp_secret"] = self._encrypt_value(item["totp_secret"])

            encrypted["passwords"].append(encrypted_item)
        return encrypted

    def _decrypt_data(self, data: dict) -> dict:
        decrypted = {"passwords": []}
        for item in data.get("passwords", []):
            decrypted_item = copy.deepcopy(item)

            if "password" in item.keys():
                decrypted_item["password"] = self._decrypt_value(item["password"])
            if "totp_secret" in item.keys():
                decrypted_item["totp_secret"] = self._decrypt_value(item["totp_secret"])

            decrypted["passwords"].append(decrypted_item)
        return decrypted

    def save(self):
        data_to_save = self._encrypt_data(self.data) if self.key else self.data
        with open(self.storage_path, "w") as storage_file:
            yaml.dump(data_to_save, storage_file)
