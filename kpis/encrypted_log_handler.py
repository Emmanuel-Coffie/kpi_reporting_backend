from cryptography.fernet import Fernet, InvalidToken
import logging
import base64
import binascii

class EncryptedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    def __init__(self, *args, encryption_key=None, **kwargs):
        super().__init__(*args, **kwargs)
        if not encryption_key:
            raise ValueError("Encryption key is required")
        try:
            # Validate the key format
            Fernet(encryption_key)
            self.cipher = Fernet(encryption_key)
        except (ValueError, binascii.Error) as e:
            raise ValueError(f"Invalid Fernet key: {str(e)}")

    def emit(self, record):
        try:
            msg = self.format(record)
            encrypted_msg = self.cipher.encrypt(msg.encode())
            self.stream.write(encrypted_msg + b'\n')
            self.flush()
        except Exception as e:
            print(f"Error in encrypted log handler: {str(e)}")
            raise