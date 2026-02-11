"""
Container Plugin Configuration Model
"""
import logging
from cryptography.fernet import Fernet, InvalidToken
from CTFd.models import db

logger = logging.getLogger(__name__)


class ContainerConfig(db.Model):
    """
    Plugin configuration (key-value store)
    """
    __tablename__ = 'container_config'
    
    key = db.Column(db.String(255), primary_key=True)
    value = db.Column(db.Text)
    
    @staticmethod
    def get(key, default=None):
        """Get config value"""
        config = ContainerConfig.query.filter_by(key=key).first()
        return config.value if config else default
    
    @staticmethod
    def set(key, value):
        """Set config value"""
        config = ContainerConfig.query.filter_by(key=key).first()
        if not config:
            config = ContainerConfig(key=key, value=value)
            db.session.add(config)
        else:
            config.value = value
        db.session.commit()
    
    @staticmethod
    def get_all():
        """Get all config as dict"""
        configs = ContainerConfig.query.all()
        return {c.key: c.value for c in configs}

    @staticmethod
    def _get_or_create_encryption_key() -> str:
        """Get the Fernet encryption key, creating one if it doesn't exist."""
        key = ContainerConfig.get('flag_encryption_key')
        if not key:
            key = Fernet.generate_key().decode()
            ContainerConfig.set('flag_encryption_key', key)
            logger.info("Generated new encryption key")
        return key

    @staticmethod
    def encrypt_value(plaintext: str) -> str:
        """
        Encrypt a plaintext string using the plugin's Fernet key.
        Returns a Fernet token string (safe for DB storage).
        """
        if not plaintext:
            return plaintext
        key = ContainerConfig._get_or_create_encryption_key()
        cipher = Fernet(key.encode())
        return cipher.encrypt(plaintext.encode()).decode()

    @staticmethod
    def decrypt_value(encrypted_text: str) -> str:
        """
        Decrypt a Fernet-encrypted string.
        Falls back to returning the original value if decryption fails
        (backward-compatibility with pre-existing plaintext values).
        """
        if not encrypted_text:
            return encrypted_text
        key = ContainerConfig.get('flag_encryption_key')
        if not key:
            return encrypted_text
        try:
            cipher = Fernet(key.encode())
            return cipher.decrypt(encrypted_text.encode()).decode()
        except (InvalidToken, Exception):
            return encrypted_text
