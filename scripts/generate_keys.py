#!/usr/bin/env python3
"""
Kyber Key Generation Script for QSS4

This script generates and manages Kyber post-quantum cryptographic keypairs
for the QSS4 secure storage system.
"""

import os
import sys
import json
import click
from pathlib import Path
from datetime import datetime

# Add the parent directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from mineral.encryption.key_manager import key_manager, KeyManager
from mineral.encryption.hybrid_encryptor import KyberKEM
from core.config import settings
from cryptography.fernet import Fernet

@click.group()
def cli():
    """QSS4 Kyber Key Management CLI"""
    pass

@cli.command()
@click.option('--encrypt', is_flag=True, help='Encrypt private key with Fernet')
@click.option('--force', is_flag=True, help='Overwrite existing keypair')
@click.option('--backup', is_flag=True, help='Backup existing keypair before generating new one')
def generate(encrypt, force, backup):
    """Generate a new Kyber-1024 keypair"""
    
    print("🔐 QSS4 Kyber Key Generator")
    print("=" * 40)
    
    try:
        # Check if keypair already exists
        if key_manager.keypair_exists() and not force:
            print("⚠️  Kyber keypair already exists!")
            print(f"   Location: {key_manager.key_dir}")
            
            if click.confirm('Generate new keypair anyway? (This will backup the old one)'):
                backup = True
            else:
                print("❌ Key generation cancelled")
                return
        
        # Backup existing keypair if requested
        if backup and key_manager.keypair_exists():
            print("💾 Backing up existing keypair...")
            try:
                backup_result = key_manager.rotate_keypair()
                print(f"✅ Backup created successfully")
            except Exception as e:
                print(f"❌ Backup failed: {e}")
                if not click.confirm('Continue without backup?'):
                    return
        
        # Check Fernet key for encryption
        if encrypt:
            if not settings.fernet_key:
                print("🔑 No Fernet key found. Generating one...")
                new_fernet_key = Fernet.generate_key()
                print(f"📋 Generated Fernet key: {new_fernet_key.decode()}")
                print("⚠️  IMPORTANT: Set this as FERNET_KEY environment variable!")
                print("   export FERNET_KEY='<key_above>'")
                
                if not click.confirm('Continue with key generation?'):
                    return
        
        # Generate new keypair
        print("🔧 Generating Kyber-1024 keypair...")
        print("   This may take a few moments...")
        
        with click.progressbar(length=100, label='Generating keys') as bar:
            # Initialize KEM
            kem = KyberKEM()
            bar.update(25)
            
            # Generate keypair
            public_key, private_key = kem.generate_keypair()
            bar.update(50)
            
            # Save keypair
            metadata = key_manager.save_keypair(public_key, private_key, encrypt=encrypt)
            bar.update(100)
        
        print("✅ Kyber keypair generated successfully!")
        
        # Display key information
        print("\n📋 Key Information:")
        print(f"   Algorithm: {metadata['algorithm']}")
        print(f"   Public Key Size: {metadata['public_key_size']} bytes")
        print(f"   Private Key Size: {metadata['private_key_size']} bytes")
        print(f"   Encrypted: {'Yes' if metadata['encrypted'] else 'No'}")
        print(f"   Public Key Path: {metadata['public_key_path']}")
        print(f"   Private Key Path: {metadata['private_key_path']}")
        
        # Security recommendations
        print("\n🛡️  Security Recommendations:")
        print("   • Store private key in secure location")
        print("   • Set appropriate file permissions (600)")
        print("   • Consider hardware security module (HSM) for production")
        print("   • Keep backup of keys in secure offline storage")
        
        if encrypt:
            print("   • Ensure FERNET_KEY environment variable is set")
            print("   • Store Fernet key separately from Kyber keys")
        
    except Exception as e:
        print(f"❌ Key generation failed: {e}")
        return 1

@cli.command()
def info():
    """Display information about current keypair"""
    
    print("🔍 Kyber Keypair Information")
    print("=" * 30)
    
    try:
        if not key_manager.keypair_exists():
            print("❌ No Kyber keypair found")
            print(f"   Expected location: {key_manager.key_dir}")
            print("   Run 'python scripts/generate_keys.py generate' to create one")
            return
        
        # Load metadata
        metadata_path = key_manager.key_dir / "kyber_metadata.json"
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        print("✅ Keypair found!")
        print(f"\n📋 Details:")
        print(f"   Algorithm: {metadata['algorithm']}")
        print(f"   Public Key Size: {metadata['public_key_size']} bytes")
        print(f"   Private Key Size: {metadata['private_key_size']} bytes")
        print(f"   Encrypted: {'Yes' if metadata['encrypted'] else 'No'}")
        print(f"   Public Key: {metadata['public_key_path']}")
        print(f"   Private Key: {metadata['private_key_path']}")
        
        # Check file permissions
        pub_path = Path(metadata['public_key_path'])
        priv_path = Path(metadata['private_key_path'])
        
        print(f"\n🔒 File Permissions:")
        if pub_path.exists():
            pub_perms = oct(pub_path.stat().st_mode)[-3:]
            print(f"   Public Key: {pub_perms} {'✅' if pub_perms == '644' else '⚠️'}")
        
        if priv_path.exists():
            priv_perms = oct(priv_path.stat().st_mode)[-3:]
            print(f"   Private Key: {priv_perms} {'✅' if priv_perms == '600' else '⚠️'}")
        
        # Test key loading
        print(f"\n🧪 Testing key loading...")
        try:
            public_key = key_manager.get_public_key()
            print(f"   Public Key: ✅ ({len(public_key)} bytes)")
        except Exception as e:
            print(f"   Public Key: ❌ {e}")
        
        try:
            private_key = key_manager.get_private_key()
            print(f"   Private Key: ✅ ({len(private_key)} bytes)")
        except Exception as e:
            print(f"   Private Key: ❌ {e}")
        
        # Check backup directory
        backup_dir = key_manager.key_dir / "backup"
        if backup_dir.exists():
            backups = list(backup_dir.glob("*_kyber_*.key"))
            print(f"\n💾 Backups: {len(backups)} found")
            for backup in sorted(backups)[-3:]:  # Show last 3 backups
                print(f"   • {backup.name}")
        
    except Exception as e:
        print(f"❌ Error reading keypair info: {e}")
        return 1

@cli.command()
def test():
    """Test Kyber keypair functionality"""
    
    print("🧪 Testing Kyber Keypair")
    print("=" * 25)
    
    try:
        if not key_manager.keypair_exists():
            print("❌ No keypair found. Generate one first.")
            return 1
        
        # Test key loading
        print("📂 Loading keys...")
        public_key = key_manager.get_public_key()
        private_key = key_manager.get_private_key()
        print(f"✅ Keys loaded (pub: {len(public_key)} bytes, priv: {len(private_key)} bytes)")
        
        # Test KEM operations
        print("🔐 Testing KEM operations...")
        kem = KyberKEM()
        
        # Test encapsulation
        shared_secret, ciphertext = kem.encapsulate(public_key)
        print(f"✅ Encapsulation successful (secret: {len(shared_secret)} bytes, ct: {len(ciphertext)} bytes)")
        
        # Test decapsulation
        recovered_secret = kem.decapsulate(private_key, ciphertext)
        print(f"✅ Decapsulation successful (secret: {len(recovered_secret)} bytes)")
        
        # Verify secrets match
        if shared_secret == recovered_secret:
            print("✅ Shared secrets match - KEM working correctly!")
        else:
            print("❌ Shared secrets don't match - KEM failed!")
            return 1
        
        # Test with hybrid encryptor
        print("🔄 Testing hybrid encryption...")
        from mineral.encryption.hybrid_encryptor import KyberAESHybridEncryptor
        import io
        
        encryptor = KyberAESHybridEncryptor()
        test_data = b"Hello, QSS4! This is a test of the hybrid encryption system."
        test_stream = io.BytesIO(test_data)
        
        # Encrypt
        encrypted_stream, kem_ciphertext, nonce = encryptor.encrypt_with_public_key(test_stream, public_key)
        print(f"✅ Hybrid encryption successful")
        
        # Decrypt
        decrypted_stream = encryptor.decrypt_with_private_key(encrypted_stream, private_key, kem_ciphertext, nonce)
        decrypted_data = decrypted_stream.read()
        print(f"✅ Hybrid decryption successful")
        
        # Verify data
        if test_data == decrypted_data:
            print("✅ Data integrity verified - Hybrid encryption working correctly!")
        else:
            print("❌ Data corruption detected - Hybrid encryption failed!")
            return 1
        
        print(f"\n🎉 All tests passed! Kyber keypair is working correctly.")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return 1

@cli.command()
@click.confirmation_option(prompt='Are you sure you want to rotate the keypair?')
def rotate():
    """Rotate Kyber keypair (generate new one and backup old)"""
    
    print("🔄 Rotating Kyber Keypair")
    print("=" * 26)
    
    try:
        if not key_manager.keypair_exists():
            print("❌ No existing keypair found. Use 'generate' command instead.")
            return 1
        
        print("🔧 Generating new keypair and backing up old one...")
        
        with click.progressbar(length=100, label='Rotating keys') as bar:
            metadata = key_manager.rotate_keypair()
            bar.update(100)
        
        print("✅ Keypair rotation completed!")
        print(f"\n📋 New Key Information:")
        print(f"   Algorithm: {metadata['algorithm']}")
        print(f"   Public Key Size: {metadata['public_key_size']} bytes")
        print(f"   Private Key Size: {metadata['private_key_size']} bytes")
        print(f"   Public Key Path: {metadata['public_key_path']}")
        print(f"   Private Key Path: {metadata['private_key_path']}")
        
        print(f"\n⚠️  Important Notes:")
        print(f"   • Old keypair backed up to backup/ directory")
        print(f"   • Files encrypted with old key will need re-encryption")
        print(f"   • Update any external references to the public key")
        
    except Exception as e:
        print(f"❌ Keypair rotation failed: {e}")
        return 1

@cli.command()
def backup():
    """Create backup of current keypair"""
    
    print("💾 Backing Up Kyber Keypair")
    print("=" * 27)
    
    try:
        if not key_manager.keypair_exists():
            print("❌ No keypair found to backup")
            return 1
        
        # Create backup
        backup_dir = key_manager.key_dir / "backup"
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Copy files
        import shutil
        for file_name in ["kyber_public.key", "kyber_private.key", "kyber_metadata.json"]:
            src_path = key_manager.key_dir / file_name
            if src_path.exists():
                dst_path = backup_dir / f"{timestamp}_{file_name}"
                shutil.copy2(src_path, dst_path)
                print(f"✅ Backed up {file_name}")
        
        print(f"\n💾 Backup completed successfully!")
        print(f"   Location: {backup_dir}")
        print(f"   Timestamp: {timestamp}")
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        return 1

@cli.command()
def clean():
    """Clean up old backup files"""
    
    print("🧹 Cleaning Up Old Backups")
    print("=" * 26)
    
    try:
        backup_dir = key_manager.key_dir / "backup"
        if not backup_dir.exists():
            print("✅ No backup directory found")
            return
        
        # Find backup files
        backup_files = list(backup_dir.glob("*_kyber_*"))
        
        if not backup_files:
            print("✅ No backup files found")
            return
        
        # Group by timestamp
        backups = {}
        for file_path in backup_files:
            timestamp = file_path.name.split('_')[0]
            if timestamp not in backups:
                backups[timestamp] = []
            backups[timestamp].append(file_path)
        
        print(f"📋 Found {len(backups)} backup sets:")
        for timestamp in sorted(backups.keys(), reverse=True):
            files = backups[timestamp]
            print(f"   • {timestamp}: {len(files)} files")
        
        # Keep only last 5 backups
        if len(backups) > 5:
            old_backups = sorted(backups.keys())[:-5]
            
            if click.confirm(f'Delete {len(old_backups)} old backup sets?'):
                deleted_count = 0
                for timestamp in old_backups:
                    for file_path in backups[timestamp]:
                        file_path.unlink()
                        deleted_count += 1
                
                print(f"✅ Cleaned up {deleted_count} old backup files")
            else:
                print("❌ Cleanup cancelled")
        else:
            print("✅ No cleanup needed (≤5 backup sets)")
        
    except Exception as e:
        print(f"❌ Cleanup failed: {e}")
        return 1

if __name__ == '__main__':
    cli()
