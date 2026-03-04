"""Command-line interface for FileCryptor."""

import sys
import click
from pathlib import Path

from . import __version__
from .core import FileCryptor
from .utils import setup_logging
from .exceptions import CryptorError

# Color-coded output helpers
def success(msg): return click.style(msg, fg='green', bold=True)
def error(msg): return click.style(msg, fg='red', bold=True)
def warning(msg): return click.style(msg, fg='yellow')
def info(msg): return click.style(msg, fg='cyan')


@click.group()
@click.version_option(version=__version__, prog_name="FileCryptor")
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose logging.')
@click.pass_context
def cli(ctx, verbose):
    """
    FileCryptor: Enterprise-grade file encryption utility.

    Uses Fernet (AES-128-CBC + HMAC-SHA256) for authenticated encryption,
    providing strong confidentiality and integrity guarantees.

    \b
    Security Notice:
    - Keep your key file SAFE and PRIVATE
    - Never commit keys to version control
    - Lost keys = permanent data loss
    - Use strong file permissions (0600)

    \b
    Examples:
        # Generate a new key
        filecryptor generate -o my.key

        # Encrypt a file
        filecryptor encrypt -i document.pdf -k my.key

        # Decrypt a file
        filecryptor decrypt -i document.pdf.enc -k my.key
    """
    ctx.ensure_object(dict)
    setup_logging(verbose=verbose)


@cli.command()
@click.option(
    '-o', '--output',
    'output_path',
    default='master.key',
    type=click.Path(),
    help='Output path for the generated key.',
    show_default=True
)
def generate(output_path):
    """
    Generate a new encryption key and save it securely.

    The key is a 32-byte Fernet key (256-bit security).
    Store it in a secure location with restricted permissions.
    """
    try:
        click.echo(info("\n🔐 Generating new encryption key..."))
        key = FileCryptor.generate_key(output_path=output_path)
        
        click.echo(success(f"\n✓ Key generated successfully!"))
        click.echo(f"  Location: {Path(output_path).resolve()}")
        click.echo(f"  Permissions: 0600 (owner read/write only)")
        click.echo(warning("\n⚠️  CRITICAL: Backup this key securely. Loss = unrecoverable data!"))
        
    except CryptorError as e:
        click.echo(error(f"\n✗ Error: {e}"))
        sys.exit(1)


@cli.command()
@click.option(
    '-i', '--input',
    'input_path',
    required=True,
    type=click.Path(exists=True),
    help='File to encrypt.'
)
@click.option(
    '-k', '--key',
    'key_path',
    required=True,
    type=click.Path(exists=True),
    help='Path to encryption key file.'
)
@click.option(
    '-o', '--output',
    'output_path',
    type=click.Path(),
    help='Output file path (defaults to <input>.enc).'
)
@click.option(
    '--overwrite',
    is_flag=True,
    help='Overwrite output file if it exists.'
)
def encrypt(input_path, key_path, output_path, overwrite):
    """
    Encrypt a file using the specified key.

    The encrypted file will have authenticated encryption,
    protecting against both confidentiality and integrity attacks.
    """
    try:
        click.echo(info("\n🔒 Starting encryption..."))
        
        # Load key and initialize cryptor
        key = FileCryptor.load_key(key_path)
        cryptor = FileCryptor(key=key)
        
        # Encrypt
        output_file = cryptor.encrypt_file(
            input_path=input_path,
            output_path=output_path,
            overwrite=overwrite
        )
        
        click.echo(success(f"\n✓ Encryption successful!"))
        click.echo(f"  Input:  {Path(input_path).resolve()}")
        click.echo(f"  Output: {output_file.resolve()}")
        click.echo(info(f"  Key:    {Path(key_path).resolve().name}"))
        
    except CryptorError as e:
        click.echo(error(f"\n✗ Encryption failed: {e}"))
        sys.exit(1)
    except Exception as e:
        click.echo(error(f"\n✗ Unexpected error: {e}"))
        sys.exit(1)


@cli.command()
@click.option(
    '-i', '--input',
    'input_path',
    required=True,
    type=click.Path(exists=True),
    help='File to decrypt.'
)
@click.option(
    '-k', '--key',
    'key_path',
    required=True,
    type=click.Path(exists=True),
    help='Path to encryption key file.'
)
@click.option(
    '-o', '--output',
    'output_path',
    type=click.Path(),
    help='Output file path (defaults to input minus .enc).'
)
@click.option(
    '--overwrite',
    is_flag=True,
    help='Overwrite output file if it exists.'
)
def decrypt(input_path, key_path, output_path, overwrite):
    """
    Decrypt a file using the specified key.

    The key must match the one used for encryption.
    Decryption will fail if the file has been tampered with.
    """
    try:
        click.echo(info("\n🔓 Starting decryption..."))
        
        # Load key and initialize cryptor
        key = FileCryptor.load_key(key_path)
        cryptor = FileCryptor(key=key)
        
        # Decrypt
        output_file = cryptor.decrypt_file(
            input_path=input_path,
            output_path=output_path,
            overwrite=overwrite
        )
        
        click.echo(success(f"\n✓ Decryption successful!"))
        click.echo(f"  Input:  {Path(input_path).resolve()}")
        click.echo(f"  Output: {output_file.resolve()}")
        click.echo(info(f"  Key:    {Path(key_path).resolve().name}"))
        
    except CryptorError as e:
        click.echo(error(f"\n✗ Decryption failed: {e}"))
        sys.exit(1)
    except Exception as e:
        click.echo(error(f"\n✗ Unexpected error: {e}"))
        sys.exit(1)


if __name__ == '__main__':
    cli()
