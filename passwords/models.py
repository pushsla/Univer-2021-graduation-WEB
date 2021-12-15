import cryptography.fernet
from django.contrib.auth.models import AbstractUser
from django.db import models
from cryptography.fernet import Fernet

from .lib.DTO import DecryptedWallet, DecryptedPassword
from .lib.crypto import *
# Create your models here.

BYTE_LEN = 3
BYTE_ORGER = "big"


class Password(models.Model):
    enc_wallet_id = models.BinaryField()
    enc_name = models.BinaryField()
    enc_url = models.BinaryField()
    enc_passw = models.BinaryField()

    def decrypt(self, decryptor: Fernet):
        try:
            return DecryptedPassword(
                self.id,
                int.from_bytes(decryptor.decrypt(self.enc_wallet_id), BYTE_ORGER),
                decryptor.decrypt(self.enc_name),
                decryptor.decrypt(self.enc_url),
                decryptor.decrypt(self.enc_passw)
            )
        except cryptography.fernet.InvalidToken:
            return DecryptedPassword(id=-1, wallet_id=-1, name=b'ERR', url=b'ERR', passw=b'ERR')


class Wallet(models.Model):
    enc_user_id = models.BinaryField()
    enc_name = models.BinaryField()
    code_word = models.BinaryField(default=b'PIZDA')

    def is_password_valid(self, password_hash: bytes) -> bool:
        try:
            decryptor = cryptor(password_hash)
            test_code_word = decryptor.decrypt(self.code_word)
            return test_code_word == self.id.to_bytes(BYTE_LEN, BYTE_ORGER)
        except cryptography.fernet.InvalidToken:
            return False

    def get_passwords(self, password_hash: bytes):
        decryptor = cryptor(password_hash)

        passwords = Password.objects.all()
        maybe = [p.decrypt(decryptor) for p in passwords]
        return [p for p in maybe if p.wallet_id == self.id]

    def decrypt(self, decryptor: Fernet):
        try:
            return DecryptedWallet(
                self.id,
                int.from_bytes(decryptor.decrypt(self.enc_user_id), BYTE_ORGER),
                decryptor.decrypt(self.enc_name)
            )
        except cryptography.fernet.InvalidToken:
            return DecryptedWallet(id=-1, user_id=-1, name='ERROR')

    def add_password(self, password_hash: bytes, data: DecryptedPassword):
        if data.wallet_id == self.id:
            encryptor = cryptor(password_hash)
            password = Password(
                enc_wallet_id=encryptor.encrypt(self.id.to_bytes(BYTE_LEN, BYTE_ORGER)),
                enc_name=encryptor.encrypt(data.name),
                enc_url=encryptor.encrypt(data.url),
                enc_passw=encryptor.encrypt(data.passw)
            )
            password.save()


class PassUser(AbstractUser):

    code_word = models.BinaryField(default=b'PIZDA')

    def is_password_valid(self, password_hash: bytes) -> bool:
        try:
            decryptor = cryptor(password_hash)
            test_code_word = decryptor.decrypt(self.code_word)
            return test_code_word == self.id.to_bytes(BYTE_LEN, BYTE_ORGER)
        except cryptography.fernet.InvalidToken:
            return False

    def get_wallets(self, password_hash: bytes):
        decryptor = cryptor(password_hash)

        wallets = Wallet.objects.all()
        maybe = [w.decrypt(decryptor) for w in wallets]
        return [w for w in maybe if w.user_id == self.id]

    def add_wallet(self, masterpassword_hash: bytes, data: DecryptedWallet, walletpassword_hash: bytes):
        if data.user_id == self.id:
            encryptor = cryptor(masterpassword_hash)
            wallet_encryptor = cryptor(walletpassword_hash)
            wallet = Wallet(
                enc_user_id=encryptor.encrypt(self.id.to_bytes(BYTE_LEN, BYTE_ORGER)),
                enc_name=encryptor.encrypt(data.name),
            )
            wallet.save()
            wallet.code_word = wallet_encryptor.encrypt(wallet.id.to_bytes(BYTE_LEN, BYTE_ORGER))
            wallet.save()
