import click
import os
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
import sys

# --- Core Encryption Functions ---

def generate_fernet_key(master_key_file):
    """Generates a new, random 32-byte Fernet key and saves it to a file."""
    try:
        # Fernet keys are 32 URL-safe base64-encoded bytes (256 bits).
        key = Fernet.generate_key()

        with open(master_key_file, 'wb') as f:
            f.write(key)

        click.echo(f"\n[+] SUCCESS: New encryption key generated and saved to '{master_key_file}'")
        click.echo("    KEEP THIS FILE SAFE! Without it, encrypted files cannot be recovered.")
        click.echo("    Key Bytes: " + key.decode()[:10] + "...")
    except Exception as e:
        click.echo(f"\n[!] ERROR: Failed to generate or save key: {e}")

def load_key(master_key_file):
    """Loads the encryption key from a file."""
    try:
        with open(master_key_file, 'rb') as f:
            key = f.read()
            return key
    except FileNotFoundError:
        click.echo(f"\n[!] ERROR: Key file not found at '{master_key_file}'.")
        return None
    except Exception as e:
        click.echo(f"\n[!] ERROR: Could not load key: {e}")
        return None

def encrypt_file(input_filepath, output_filepath, key):
    """Encrypts a file using the provided Fernet key."""
    try:
        f = Fernet(key)

        # Read the file content
        with open(input_filepath, 'rb') as file:
            file_data = file.read()

        # Encrypt the data
        encrypted_data = f.encrypt(file_data)

        # Write the encrypted file
        with open(output_filepath, 'wb') as file:
            file.write(encrypted_data)

        click.echo(f"\n[+] SUCCESS: File encrypted.")
        click.echo(f"    Input: {input_filepath}")
        click.echo(f"    Output: {output_filepath}")
        # Removed the key display for security reasons, it was also causing an error
        # click.echo(f"    Key used: '{os.path.basename(key_file_path)}'")

    except FileNotFoundError:
        click.echo(f"\n[!] ERROR: Input file not found at '{input_filepath}'.")
    except Exception as e:
        click.echo(f"\n[!] ERROR: An error occurred during encryption: {e}")

def decrypt_file(input_filepath, output_filepath, key):
    """Decrypts a file using the provided Fernet key."""
    try:
        f = Fernet(key)

        # Read the encrypted data
        with open(input_filepath, 'rb') as file:
            encrypted_data = file.read()

        # Decrypt the data
        decrypted_data = f.decrypt(encrypted_data)

        # Write the decrypted file
        with open(output_filepath, 'wb') as file:
            file.write(decrypted_data)

        click.echo(f"\n[+] SUCCESS: File decrypted.")
        click.echo(f"    Input: {input_filepath}")
        click.echo(f"    Output: {output_filepath}")

    except FileNotFoundError:
        click.echo(f"\n[!] ERROR: Input file not found at '{input_filepath}'.")
    except InvalidToken:
        click.echo("\n[!] ERROR: Decryption failed. The key is incorrect or the file is corrupted.")
    except Exception as e:
        click.echo(f"\n[!] ERROR: An error occurred during decryption: {e}")

# --- CLI Implementation using Click ---

@click.group()
def cli():
    """
    AES-256 File Cryptor: A robust, command-line file encryption utility.

    Uses Fernet (which is based on AES-128-CTR and HMAC-SHA256)
    for authenticated encryption, providing strong confidentiality and integrity.
    """
    pass

@cli.command(name='generate')
@click.option('-o', '--output', 'key_file_path', default='master.key',
              help='Output file path for the generated key.', show_default=True)
def generate_command(key_file_path):
    """Generates a new, secure encryption key and saves it to a file."""
    generate_fernet_key(key_file_path)

@cli.command(name='enc')
@click.option('-i', '--input', 'input_filepath', required=True,
              help='Path to the file to be encrypted.')
@click.option('-k', '--keyfile', 'key_file_path', required=True,
              help='Path to the master encryption key file.')
@click.option('-o', '--output', 'output_filepath', default=None,
              help='Optional output path for the encrypted file. Defaults to <input>.enc')
def encrypt_command(input_filepath, key_file_path, output_filepath):
    """Encrypts a file using the specified key file."""

    key = load_key(key_file_path)
    if key is None:
        return

    if output_filepath is None:
        output_filepath = input_filepath + ".enc"

    encrypt_file(input_filepath, output_filepath, key)


@cli.command(name='dec')
@click.option('-i', '--input', 'input_filepath', required=True,
              help='Path to the file to be decrypted.')
@click.option('-k', '--keyfile', 'key_file_path', required=True,
              help='Path to the master encryption key file.')
@click.option('-o', '--output', 'output_filepath', default=None,
              help='Optional output path for the decrypted file. Defaults to input file minus .enc')
def decrypt_command(input_filepath, key_file_path, output_filepath):
    """Decrypts a file using the specified key file."""

    key = load_key(key_file_path)
    if key is None:
        return

    if output_filepath is None:
        # Default behavior: remove .enc suffix if present, otherwise append .dec
        if input_filepath.endswith(".enc"):
            output_filepath = input_filepath[:-4]
        else:
            output_filepath = input_filepath + ".dec"

    decrypt_file(input_filepath, output_filepath, key)


if __name__ == '__main__':
    # Check if running in a Colab environment. Colab passes -f by default
    # which interferes with Click. We can detect this and pass only user args.
    if 'ipykernel' in sys.modules:
        cli(sys.argv[1:]) # Pass arguments excluding the script name
    else:
        cli()# Placeholder for encryption_tool.py
