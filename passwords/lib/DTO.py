class DecryptedWallet:
    def __init__(self, id: int, user_id: int, name: bytes):
        self.id = id
        self.user_id = user_id
        self.name = name


class DecryptedPassword:
    def __init__(self, id: int, wallet_id: int, name: bytes, url: bytes, passw: bytes):
        self.id = id
        self.wallet_id = wallet_id
        self.name = name
        self.url = url
        self.passw = passw