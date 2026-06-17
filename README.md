# Cryptor

Cryptor is a simple C# console app for encrypting and decrypting UTF-8 text with a password. It uses only APIs available in a fresh .NET install: `System.Security.Cryptography`, `System.Text.Json`, and standard console/file/process APIs.

The app supports both:

- An interactive menu when run without arguments.
- Scriptable `encrypt` and `decrypt` subcommands.

Passwords are entered through a masked prompt. In a normal terminal, each character is displayed as `*` instead of showing the real password.

## Quick Start

Build the app:

```powershell
dotnet build .\Cryptor\Cryptor.csproj
```

Run the interactive menu:

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj
```

Encrypt text from the command line:

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- encrypt --text "my secret text"
```

Decrypt a payload and print the result:

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- decrypt --text "CRYPTORv1:..." --output console
```

## What To Save

When you encrypt, the app prints a value that starts with:

```text
CRYPTORv1:
```

Save the entire `CRYPTORv1:` payload. That full payload is what you need later for decryption.

You do not need to save the salt separately. The salt, nonce, authentication tag, KDF settings, and ciphertext are all embedded inside the payload.

Your password is not stored in the payload.

## How Encryption Works

Cryptor uses:

- `AES-256-GCM` for authenticated encryption.
- `PBKDF2-HMAC-SHA512` to derive an encryption key from the password.
- A random 32-byte salt for each encryption.
- A random 12-byte AES-GCM nonce for each encryption.
- A 16-byte AES-GCM authentication tag.
- 600,000 PBKDF2 iterations by default.

The flow is:

1. You enter plaintext and a password.
2. The app generates a random salt and nonce.
3. PBKDF2 uses the password, salt, iteration count, and SHA-512 to derive a 32-byte AES key.
4. AES-256-GCM encrypts the plaintext.
5. The app stores the metadata and ciphertext together in one self-contained payload.

The salt is not secret. Its purpose is to make the derived key different every time, even if the same password is reused. This prevents attackers from using one precomputed password-guessing table across many encrypted messages.

## Why Decryption Works Without Entering Salt Separately

Decryption still uses the salt. You just do not type it manually.

The encrypted payload contains a JSON object like this before it is encoded:

```json
{
  "version": "1",
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2",
  "kdfHash": "HMACSHA512",
  "iterations": 600000,
  "salt": "...",
  "nonce": "...",
  "tag": "...",
  "ciphertext": "..."
}
```

The app base64url-encodes that JSON and prefixes it with `CRYPTORv1:` so it is easy to copy, paste, and save.

During decrypt, the app:

1. Reads the full `CRYPTORv1:` payload.
2. Decodes the embedded JSON.
3. Extracts the salt, nonce, tag, iteration count, and ciphertext.
4. Derives the same AES key from your password and the stored salt.
5. Uses AES-GCM to verify the tag and decrypt the ciphertext.

If the password is wrong or the payload was changed, AES-GCM authentication fails and the app does not print partial plaintext.

## Quantum-Safe Note

This app is password-based symmetric encryption. For that model, `AES-256-GCM` is the practical quantum-resistant choice available in fresh .NET.

Post-quantum algorithms such as ML-KEM are designed for public-key key establishment between parties. They do not replace password-based encryption unless the app also introduces key pairs and key management. Cryptor intentionally avoids that complexity.

## Interactive Usage

Run:

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj
```

The menu offers:

```text
1. Encrypt
2. Decrypt
3. Exit
```

### Interactive Encrypt

You can either:

- Type or paste plaintext.
- Read plaintext from a UTF-8 text file.

For typed or pasted text, finish input with a single dot on its own line:

```text
Enter plaintext. Finish with a single dot on its own line:
This is my secret.
.
```

The app asks for the password twice when encrypting.

### Interactive Decrypt

You can either:

- Type or paste the encrypted payload.
- Read the encrypted payload from a UTF-8 text file.

After decrypting, choose where the plaintext should go:

- Print to console.
- Save to a UTF-8 file.
- Copy to clipboard.

## Command-Line Usage

General usage:

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- encrypt [--text <text> | --in <file>] [--out <file>]
dotnet run --project .\Cryptor\Cryptor.csproj -- decrypt [--text <payload> | --in <file>] [--output console|file|clipboard] [--out <file>]
```

The `--` tells `dotnet run` to pass the remaining arguments to the app.

### Encrypt Text

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- encrypt --text "my secret text"
```

The app prompts for a password and then prints:

- The full encrypted payload.
- Metadata including algorithm, KDF, iterations, salt, nonce, and tag.

### Encrypt From A File

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- encrypt --in .\plain.txt --out .\encrypted.txt
```

This reads plaintext from `plain.txt` and writes the full encrypted payload to `encrypted.txt`.

Plaintext file content is not trimmed before encryption, so leading/trailing whitespace and newlines are preserved.

### Decrypt To Console

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- decrypt --text "CRYPTORv1:..." --output console
```

### Decrypt From A File To A File

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- decrypt --in .\encrypted.txt --output file --out .\decrypted.txt
```

When reading encrypted payloads from files, surrounding whitespace is trimmed. This makes it safe if the saved payload file ends with a newline.

### Decrypt To Clipboard

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- decrypt --in .\encrypted.txt --output clipboard
```

Clipboard support uses existing platform tools:

- Windows: `clip.exe`
- macOS: `pbcopy`
- Linux Wayland: `wl-copy`
- Linux X11: `xclip` or `xsel`

If no supported clipboard tool is found, the app prints an error. Use `--output file` or `--output console` instead.

## Avoiding Shell History For Secrets

For better secrecy, avoid putting plaintext directly in `--text` if your shell history is enabled.

Instead, run:

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- encrypt
```

If no `--text` or `--in` is provided, the app prompts for the plaintext interactively.

## Inspecting Payload Metadata Manually

The app prints metadata when encrypting. If you already have a payload and want to inspect its metadata manually, use PowerShell:

```powershell
$payload = 'CRYPTORv1:PASTE_PAYLOAD_HERE'

$encoded = $payload.Substring('CRYPTORv1:'.Length)
$base64 = $encoded.Replace('-', '+').Replace('_', '/')

if (($base64.Length % 4) -ne 0) {
  $base64 = $base64.PadRight($base64.Length + 4 - ($base64.Length % 4), '=')
}

$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
$json | ConvertFrom-Json | Select-Object version,algorithm,kdf,kdfHash,iterations,salt,nonce,tag
```

Do not remove or edit the metadata fields inside a real payload. Decryption depends on them.

## Error Behavior

Common failures are handled without stack traces:

- Wrong password or changed ciphertext: decryption fails authentication.
- Missing `CRYPTORv1:` prefix: invalid encrypted payload.
- Invalid base64/base64url: invalid encrypted payload.
- `--text` and `--in` together: invalid usage.
- `--output file` without `--out`: invalid usage.
- Clipboard tool unavailable: clipboard error with a suggestion to use file or console output.

## Security Notes

- Use a strong, unique password. Password strength still matters because attackers can guess passwords offline if they obtain the encrypted payload.
- The salt, nonce, tag, algorithm name, KDF name, and iteration count are not secret.
- The password is the secret. Losing it means the payload cannot be decrypted.
- The full payload must be preserved. Saving only the ciphertext or only the salt is not enough.
- This app is meant for UTF-8 text, not arbitrary binary file encryption.
- Clipboard output is convenient but may be visible to clipboard history tools or other local software.

## Project Layout

```text
CryptorApp.slnx
Cryptor/
  Cryptor.csproj
  Program.cs
README.md
```

## Development Checks

Build:

```powershell
dotnet build .\Cryptor\Cryptor.csproj
```

Basic manual round trip:

```powershell
dotnet run --project .\Cryptor\Cryptor.csproj -- encrypt --text "hello"
dotnet run --project .\Cryptor\Cryptor.csproj -- decrypt --text "CRYPTORv1:..." --output console
```
