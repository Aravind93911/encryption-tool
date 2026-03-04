# 🔐 FileCryptor

Enterprise-grade command-line file encryption utility using **Fernet** (AES-128 in CBC mode with HMAC-SHA256 for authenticated encryption).

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Cryptography](https://img.shields.io/badge/security-cryptography-green.svg)](https://cryptography.io/)

## 🎯 Features

- ✅ **Military-Grade Encryption**: Fernet (AES-128-CBC + HMAC-SHA256)
- ✅ **Authenticated Encryption**: Protects against tampering
- ✅ **Secure Key Management**: 32-byte (256-bit) keys with safe permissions
- ✅ **Simple CLI**: Intuitive commands with rich output
- ✅ **Production-Ready**: Logging, error handling, type hints
- ✅ **Cross-Platform**: Works on Linux, macOS, Windows

## 📦 Installation

```bash
# From source (recommended for development)
git clone https://github.com/Aravind93911/file-cryptor.git
cd file-cryptor
pip install -e .

# Or install dependencies only
pip install -r requirements.txt
```

## 🚀 Quick Start

```bash
# 1. Generate encryption key
filecryptor generate -o secret.key

# 2. Encrypt a file
filecryptor encrypt -i document.pdf -k secret.key

# 3. Decrypt the file
filecryptor decrypt -i document.pdf.enc -k secret.key
```

## 📖 Usage

### Generate Key
```bash
filecryptor generate [OPTIONS]

Options:
  -o, --output PATH  Output path for key (default: master.key)
  -v, --verbose      Enable debug logging
  --help             Show help message
```

### Encrypt File
```bash
filecryptor encrypt [OPTIONS]

Options:
  -i, --input PATH   File to encrypt (required)
  -k, --key PATH     Encryption key file (required)
  -o, --output PATH  Output file (default: <input>.enc)
  --overwrite        Overwrite existing output
  -v, --verbose      Enable debug logging
```

### Decrypt File
```bash
filecryptor decrypt [OPTIONS]

Options:
  -i, --input PATH   File to decrypt (required)
  -k, --key PATH     Encryption key file (required)
  -o, --output PATH  Output file (default: input minus .enc)
  --overwrite        Overwrite existing output
  -v, --verbose      Enable debug logging
```

## 🛡️ Security Considerations

1. **Key Storage**: Never commit keys to version control. Use `.gitignore`.
2. **Permissions**: Keys are automatically set to `0600` (owner read/write only).
3. **Backups**: Lost keys = permanent data loss. Backup securely!
4. **File Size**: Tested up to 500MB. Larger files may require chunking (future feature).
5. **Algorithm**: Fernet uses AES-128 (not AES-256), but with HMAC for integrity.

## 🧪 Running Tests

```bash
# Install dev dependencies
pip install -e .[dev]

# Run tests
pytest tests/ -v --cov=filecryptor
```

## 📝 Example Workflow

```bash
# Encrypt sensitive configuration
filecryptor generate -o prod.key
filecryptor encrypt -i database.conf -k prod.key -o database.conf.enc

# Commit encrypted file to Git (NOT the key!)
git add database.conf.enc
git commit -m "Add encrypted DB config"

# On production server (with key deployed separately):
filecryptor decrypt -i database.conf.enc -k /secure/prod.key -o database.conf
```

## 🤝 Contributing

Pull requests welcome! For major changes, open an issue first.

1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

## 👤 Author

**Aravind Dhakuri**  
🔗 [GitHub](https://github.com/Aravind93911) | [LinkedIn](https://www.linkedin.com/in/aravind-dhakuri-3a1880249)  
📧 aravinddhakuri@gmail.com

---

*Built with ❤️ for security engineering*
