"""
Flag Service - Flag generation and encryption
"""
import hashlib
import random
import string
import logging
from cryptography.fernet import Fernet
from CTFd.models import db
from ..models.config import ContainerConfig

logger = logging.getLogger(__name__)

# Teencode dictionary for flag obfuscation
teencode_dict = {
    'a': ['a', 'A', '4', '@'],
    'b': ['b', 'B', '|3'],
    'c': ['c', 'C', '('],
    'd': ['d', 'D'],
    'e': ['e', 'E', '3'],
    'f': ['f', 'F'],
    'g': ['g', 'G', '9'],
    'h': ['h', 'H', ''],
    'i': ['i', 'I', '1', '|'],
    'j': ['j', 'J'],
    'k': ['k', 'K'],
    'l': ['l', 'L', '1', '|_'],
    'm': ['m', 'M'],
    'n': ['n', 'N'],
    'o': ['o', 'O', '0'],
    'p': ['p', 'P'],
    'q': ['q', 'Q'],
    'r': ['r', 'R'],
    's': ['s', 'S', '5', '$'],
    't': ['t', 'T', '7'],
    'u': ['u', 'U'],
    'v': ['v', 'V'],
    'w': ['w', 'W'],
    'x': ['x', 'X'],
    'y': ['y', 'Y'],
    'z': ['z', 'Z'],
    '_': ['_', '-'],
    '{': ['{'],
    '}': ['}'],
}

# Reverse mapping for teencode: maps each teencode variant to its base letter
reverse_teencode_dict = {}
for base, variants in teencode_dict.items():
    for v in variants:
        reverse_teencode_dict[v] = base


def generate_random_teencode(flag, how_many_teencode=8):
    """
    Generate a teencode variant of a flag by randomly transforming some characters
    
    Args:
        flag: Base flag string
        how_many_teencode: Number of characters to transform (default 8)
    
    Returns:
        Teencode variant of the flag
    """
    # Robustly split flag into prefix, body, and suffix using first '{' and last '}'
    first_brace = flag.find('{')
    last_brace = flag.rfind('}')
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        flag_prefix = flag[:first_brace+1]
        flag_body = flag[first_brace+1:last_brace]
        flag_suffix = flag[last_brace:]
    else:
        flag_prefix = ''
        flag_body = flag
        flag_suffix = ''

    indices = list(range(len(flag_body)))
    transform_indices = set(random.sample(indices, min(how_many_teencode, len(flag_body))))

    new_chars = []
    for i, char in enumerate(flag_body):
        base_char = reverse_teencode_dict.get(char, char)
        options = teencode_dict.get(base_char.lower(), [char])
        if i in transform_indices:
            filtered_options = [o for o in options if o != char]
            if filtered_options:
                new_chars.append(random.choice(filtered_options))
            else:
                new_chars.append(char)
        else:
            new_chars.append(char)
    return flag_prefix + ''.join(new_chars) + flag_suffix


class FlagService:
    """
    Service to generate and manage flags
    """
    
    def __init__(self):
        """Initialize flag service"""
        # Get or create encryption key
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key.encode())
    
    def _get_or_create_encryption_key(self) -> str:
        """Get encryption key from config or create new one"""
        key = ContainerConfig.get('flag_encryption_key')
        if not key:
            # Generate new Fernet key
            key = Fernet.generate_key().decode()
            ContainerConfig.set('flag_encryption_key', key)
            logger.info("Generated new flag encryption key")
        return key
    
    def generate_flag(self, challenge, account_id=None) -> str:
        """
        Generate flag for challenge using teencode method
        
        Args:
            challenge: ContainerChallenge object
            account_id: Team or User ID (optional, but recommended for uniqueness)
        
        Returns:
            Plain text flag (with teencode obfuscation)
        """
        import secrets
        import hmac
        import hashlib
        
        if challenge.flag_mode == 'static':
            # Static flag: just prefix + suffix
            base_flag = f"{challenge.flag_prefix}{challenge.flag_suffix}"
        else:
            # Random flag: generate base flag first
            length = challenge.random_flag_length or 16
            alphabet = string.ascii_letters + string.digits
            random_part = ''.join(secrets.choice(alphabet) for _ in range(length))
            
            # If account_id is provided, append a unique fingerprint based on account + challenge
            if account_id:
                # Use encryption key as salt for HMAC
                salt = self.encryption_key.encode()
                msg = f"{account_id}:{challenge.id}".encode()
                fingerprint = hmac.new(salt, msg, hashlib.sha256).hexdigest()[:8]
                
                # Combine: prefix + random + fingerprint + suffix
                base_flag = f"{challenge.flag_prefix}{random_part}{fingerprint}{challenge.flag_suffix}"
            else:
                base_flag = f"{challenge.flag_prefix}{random_part}{challenge.flag_suffix}"
        
        # Apply teencode transformation (how_many_teencode characters)
        # Get teencode count from config or use default 8
        teencode_count = int(ContainerConfig.get('teencode_count', '8'))
        flag = generate_random_teencode(base_flag, how_many_teencode=teencode_count)
        
        return flag
    
    def encrypt_flag(self, flag: str) -> str:
        """
        Encrypt flag for storage
        
        Args:
            flag: Plain text flag
        
        Returns:
            Encrypted flag (base64 encoded)
        """
        encrypted = self.cipher.encrypt(flag.encode())
        return encrypted.decode()
    
    def decrypt_flag(self, encrypted_flag: str) -> str:
        """
        Decrypt flag
        
        Args:
            encrypted_flag: Encrypted flag
        
        Returns:
            Plain text flag
        """
        try:
            decrypted = self.cipher.decrypt(encrypted_flag.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt flag: {e}")
            raise Exception("Failed to decrypt flag")
    
    @staticmethod
    def hash_flag(flag: str) -> str:
        """
        Hash flag using SHA256
        
        Args:
            flag: Plain text flag
        
        Returns:
            Hex digest of flag hash
        """
        return hashlib.sha256(flag.encode()).hexdigest()
    
    def create_flag_record(self, instance, challenge, account_id, flag_plaintext):
        """
        Create flag record in database
        
        Args:
            instance: ContainerInstance object
            challenge: ContainerChallenge object
            account_id: Team or user ID
            flag_plaintext: Plain text flag
        
        Returns:
            ContainerFlag object
        """
        from ..models.flag import ContainerFlag
        
        flag_hash = self.hash_flag(flag_plaintext)
        flag_encrypted = self.encrypt_flag(flag_plaintext)
        
        flag_record = ContainerFlag(
            instance_id=instance.id,
            flag_hash=flag_hash,
            challenge_id=challenge.id,
            account_id=account_id,
            flag_status='temporary'
        )
        
        db.session.add(flag_record)
        db.session.flush()  # Get the ID
        
        return flag_record
