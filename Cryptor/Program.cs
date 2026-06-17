
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal static class Program
{
    private const string PayloadPrefix = "CRYPTORv1:";
    private const string PayloadVersion = "1";
    private const string Algorithm = "AES-256-GCM";
    private const string Kdf = "PBKDF2";
    private const string KdfHash = "HMACSHA512";
    private const int KeySizeBytes = 32;
    private const int SaltSizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;
    private const int DefaultIterations = 600_000;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                RunInteractiveMenu();
                return 0;
            }

            return RunCommand(args);
        }
        catch (UsageException ex)
        {
            Console.Error.WriteLine(ex.Message);
            Console.Error.WriteLine();
            PrintUsage(Console.Error);
            return 2;
        }
        catch (AuthenticationTagMismatchException)
        {
            Console.Error.WriteLine("Decryption failed. The password is wrong, or the encrypted payload was changed.");
            return 3;
        }
        catch (CryptographicException ex)
        {
            Console.Error.WriteLine($"Cryptographic error: {ex.Message}");
            return 3;
        }
        catch (InvalidPayloadException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 4;
        }
        catch (ClipboardException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 6;
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"File error: {ex.Message}");
            return 5;
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.Error.WriteLine($"Access error: {ex.Message}");
            return 5;
        }
    }

    private static int RunCommand(string[] args)
    {
        string command = args[0].ToLowerInvariant();
        CommandOptions options = CommandOptions.Parse(args.Skip(1).ToArray());

        return command switch
        {
            "encrypt" => RunEncryptCommand(options),
            "decrypt" => RunDecryptCommand(options),
            "-h" or "--help" or "help" => PrintUsageAndReturn(),
            _ => throw new UsageException($"Unknown command '{args[0]}'.")
        };
    }

    private static int RunEncryptCommand(CommandOptions options)
    {
        ValidateInputOptions(options);

        string plaintext = ReadCommandInput(options, "Plaintext", trimFileInput: false);
        char[] password = ReadPassword("Password: ");

        try
        {
            EncryptedPackage package = CryptoService.Encrypt(plaintext, password);
            string payload = PayloadCodec.Encode(package);

            if (!string.IsNullOrWhiteSpace(options.OutPath))
            {
                File.WriteAllText(options.OutPath, payload, Encoding.UTF8);
                Console.WriteLine($"Encrypted payload saved to: {options.OutPath}");
            }
            else
            {
                Console.WriteLine("Encrypted payload:");
                Console.WriteLine(payload);
            }

            PrintMetadata(package);
            Console.WriteLine("Keep the full encrypted payload. The salt alone is not enough to decrypt later.");
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password.AsSpan()));
        }
    }

    private static int RunDecryptCommand(CommandOptions options)
    {
        ValidateInputOptions(options);

        string output = options.Output?.ToLowerInvariant() ?? "console";
        if (output is not ("console" or "file" or "clipboard"))
        {
            throw new UsageException("--output must be console, file, or clipboard.");
        }

        if (output == "file" && string.IsNullOrWhiteSpace(options.OutPath))
        {
            throw new UsageException("--out is required when --output file is used.");
        }

        string payload = ReadCommandInput(options, "Encrypted payload", trimFileInput: true);
        char[] password = ReadPassword("Password: ");

        try
        {
            EncryptedPackage package = PayloadCodec.Decode(payload);
            string plaintext = CryptoService.Decrypt(package, password);

            switch (output)
            {
                case "console":
                    Console.WriteLine("Decrypted text:");
                    Console.WriteLine(plaintext);
                    break;
                case "file":
                    File.WriteAllText(options.OutPath!, plaintext, Encoding.UTF8);
                    Console.WriteLine($"Decrypted text saved to: {options.OutPath}");
                    break;
                case "clipboard":
                    Clipboard.CopyText(plaintext);
                    Console.WriteLine("Decrypted text copied to clipboard.");
                    break;
            }

            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password.AsSpan()));
        }
    }

    private static void RunInteractiveMenu()
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Cryptor");
            Console.WriteLine("1. Encrypt");
            Console.WriteLine("2. Decrypt");
            Console.WriteLine("3. Exit");
            Console.Write("Choose an option: ");

            string? choice = Console.ReadLine()?.Trim();
            Console.WriteLine();

            switch (choice)
            {
                case "1":
                    RunInteractiveEncrypt();
                    break;
                case "2":
                    RunInteractiveDecrypt();
                    break;
                case "3":
                    return;
                default:
                    Console.WriteLine("Invalid option.");
                    break;
            }
        }
    }

    private static void RunInteractiveEncrypt()
    {
        string plaintext = ReadInteractiveInput("plaintext", trimFileInput: false);
        char[] password = ReadPassword("Password: ");
        char[] confirmation = ReadPassword("Confirm password: ");

        try
        {
            if (!password.AsSpan().SequenceEqual(confirmation))
            {
                Console.WriteLine("Passwords do not match.");
                return;
            }

            EncryptedPackage package = CryptoService.Encrypt(plaintext, password);
            string payload = PayloadCodec.Encode(package);

            Console.WriteLine();
            Console.WriteLine("Encrypted payload:");
            Console.WriteLine(payload);
            Console.WriteLine();
            PrintMetadata(package);
            Console.WriteLine("Keep the full encrypted payload. The salt alone is not enough to decrypt later.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password.AsSpan()));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(confirmation.AsSpan()));
        }
    }

    private static void RunInteractiveDecrypt()
    {
        try
        {
            string payload = ReadInteractiveInput("encrypted payload", trimFileInput: true);
            char[] password = ReadPassword("Password: ");

            try
            {
                EncryptedPackage package = PayloadCodec.Decode(payload);
                string plaintext = CryptoService.Decrypt(package, password);
                WriteInteractiveDecryptionOutput(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(password.AsSpan()));
            }
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Decryption failed. The password is wrong, or the encrypted payload was changed.");
        }
        catch (InvalidPayloadException ex)
        {
            Console.WriteLine(ex.Message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ClipboardException)
        {
            Console.WriteLine(ex.Message);
        }
    }

    private static string ReadInteractiveInput(string label, bool trimFileInput)
    {
        Console.WriteLine($"1. Type or paste {label}");
        Console.WriteLine($"2. Read {label} from a UTF-8 file");
        Console.Write("Choose input method: ");

        string? choice = Console.ReadLine()?.Trim();
        if (choice == "2")
        {
            Console.Write("File path: ");
            string? path = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new IOException("A file path is required.");
            }

            string fileText = File.ReadAllText(path, Encoding.UTF8);
            return trimFileInput ? fileText.Trim() : fileText;
        }

        Console.WriteLine($"Enter {label}. Finish with a single dot on its own line:");
        return ReadUntilDotLine();
    }

    private static string ReadUntilDotLine()
    {
        StringBuilder builder = new();

        while (true)
        {
            string? line = Console.ReadLine();
            if (line == null || line == ".")
            {
                break;
            }

            if (builder.Length > 0)
            {
                builder.AppendLine();
            }

            builder.Append(line);
        }

        return builder.ToString();
    }

    private static void WriteInteractiveDecryptionOutput(string plaintext)
    {
        Console.WriteLine();
        Console.WriteLine("1. Print to console");
        Console.WriteLine("2. Save to UTF-8 file");
        Console.WriteLine("3. Copy to clipboard");
        Console.Write("Choose output method: ");

        string? choice = Console.ReadLine()?.Trim();
        switch (choice)
        {
            case "2":
                Console.Write("Output file path: ");
                string? path = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(path))
                {
                    Console.WriteLine("A file path is required.");
                    return;
                }

                File.WriteAllText(path, plaintext, Encoding.UTF8);
                Console.WriteLine($"Decrypted text saved to: {path}");
                break;
            case "3":
                Clipboard.CopyText(plaintext);
                Console.WriteLine("Decrypted text copied to clipboard.");
                break;
            default:
                Console.WriteLine("Decrypted text:");
                Console.WriteLine(plaintext);
                break;
        }
    }

    private static string ReadCommandInput(CommandOptions options, string label, bool trimFileInput)
    {
        if (!string.IsNullOrEmpty(options.Text))
        {
            return options.Text;
        }

        if (!string.IsNullOrWhiteSpace(options.InPath))
        {
            string fileText = File.ReadAllText(options.InPath, Encoding.UTF8);
            return trimFileInput ? fileText.Trim() : fileText;
        }

        Console.WriteLine($"Enter {label.ToLowerInvariant()}. Finish with a single dot on its own line:");
        return ReadUntilDotLine();
    }

    private static void ValidateInputOptions(CommandOptions options)
    {
        if (!string.IsNullOrEmpty(options.Text) && !string.IsNullOrWhiteSpace(options.InPath))
        {
            throw new UsageException("--text and --in cannot be used together.");
        }
    }

    private static char[] ReadPassword(string prompt)
    {
        Console.Write(prompt);

        if (Console.IsInputRedirected)
        {
            string redirected = Console.ReadLine() ?? string.Empty;
            return redirected.ToCharArray();
        }

        List<char> chars = [];

        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return chars.ToArray();
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (chars.Count > 0)
                {
                    chars.RemoveAt(chars.Count - 1);
                    Console.Write("\b \b");
                }

                continue;
            }

            if (char.IsControl(key.KeyChar))
            {
                continue;
            }

            chars.Add(key.KeyChar);
            Console.Write('*');
        }
    }

    private static void PrintMetadata(EncryptedPackage package)
    {
        Console.WriteLine("Metadata:");
        Console.WriteLine($"  Version: {package.Version}");
        Console.WriteLine($"  Algorithm: {package.Algorithm}");
        Console.WriteLine($"  KDF: {package.Kdf}");
        Console.WriteLine($"  KDF hash: {package.KdfHash}");
        Console.WriteLine($"  Iterations: {package.Iterations}");
        Console.WriteLine($"  Salt: {package.Salt}");
        Console.WriteLine($"  Nonce: {package.Nonce}");
        Console.WriteLine($"  Tag: {package.Tag}");
    }

    private static int PrintUsageAndReturn()
    {
        PrintUsage(Console.Out);
        return 0;
    }

    private static void PrintUsage(TextWriter writer)
    {
        writer.WriteLine("Usage:");
        writer.WriteLine("  cryptor encrypt [--text <text> | --in <file>] [--out <file>]");
        writer.WriteLine("  cryptor decrypt [--text <payload> | --in <file>] [--output console|file|clipboard] [--out <file>]");
        writer.WriteLine();
        writer.WriteLine("Run without arguments for the interactive menu.");
    }

    private sealed record CommandOptions(string? Text, string? InPath, string? OutPath, string? Output)
    {
        public static CommandOptions Parse(string[] args)
        {
            string? text = null;
            string? inPath = null;
            string? outPath = null;
            string? output = null;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];

                switch (arg)
                {
                    case "--text":
                        text = ReadValue(args, ref i, arg);
                        break;
                    case "--in":
                        inPath = ReadValue(args, ref i, arg);
                        break;
                    case "--out":
                        outPath = ReadValue(args, ref i, arg);
                        break;
                    case "--output":
                        output = ReadValue(args, ref i, arg);
                        break;
                    case "-h":
                    case "--help":
                        throw new UsageException("Help requested.");
                    default:
                        throw new UsageException($"Unknown option '{arg}'.");
                }
            }

            return new CommandOptions(text, inPath, outPath, output);
        }

        private static string ReadValue(string[] args, ref int index, string optionName)
        {
            if (index + 1 >= args.Length)
            {
                throw new UsageException($"{optionName} requires a value.");
            }

            index++;
            return args[index];
        }
    }

    private sealed class UsageException(string message) : Exception(message);
    private sealed class InvalidPayloadException(string message) : Exception(message);
    private sealed class ClipboardException(string message) : Exception(message);

    private sealed record EncryptedPackage(
        string Version,
        string Algorithm,
        string Kdf,
        string KdfHash,
        int Iterations,
        string Salt,
        string Nonce,
        string Tag,
        string Ciphertext);

    private static class CryptoService
    {
        public static EncryptedPackage Encrypt(string plaintext, char[] password)
        {
            if (!AesGcm.IsSupported)
            {
                throw new CryptographicException("AES-GCM is not supported on this platform.");
            }

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            byte[] key = new byte[KeySizeBytes];
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[TagSizeBytes];

            try
            {
                DeriveKey(password, salt, DefaultIterations, key);
                using AesGcm aes = new(key, TagSizeBytes);
                aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

                return new EncryptedPackage(
                    PayloadVersion,
                    Algorithm,
                    Kdf,
                    KdfHash,
                    DefaultIterations,
                    Convert.ToBase64String(salt),
                    Convert.ToBase64String(nonce),
                    Convert.ToBase64String(tag),
                    Convert.ToBase64String(ciphertext));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(plaintextBytes);
            }
        }

        public static string Decrypt(EncryptedPackage package, char[] password)
        {
            if (!AesGcm.IsSupported)
            {
                throw new CryptographicException("AES-GCM is not supported on this platform.");
            }

            ValidatePackage(package);

            byte[] salt = Convert.FromBase64String(package.Salt);
            byte[] nonce = Convert.FromBase64String(package.Nonce);
            byte[] tag = Convert.FromBase64String(package.Tag);
            byte[] ciphertext = Convert.FromBase64String(package.Ciphertext);
            byte[] plaintext = new byte[ciphertext.Length];
            byte[] key = new byte[KeySizeBytes];

            try
            {
                DeriveKey(password, salt, package.Iterations, key);
                using AesGcm aes = new(key, TagSizeBytes);
                aes.Decrypt(nonce, ciphertext, tag, plaintext);
                return Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        private static void DeriveKey(char[] password, byte[] salt, int iterations, byte[] destination)
        {
            Rfc2898DeriveBytes.Pbkdf2(password, salt, destination, iterations, HashAlgorithmName.SHA512);
        }

        private static void ValidatePackage(EncryptedPackage package)
        {
            if (package.Version != PayloadVersion ||
                package.Algorithm != Algorithm ||
                package.Kdf != Kdf ||
                package.KdfHash != KdfHash ||
                package.Iterations <= 0)
            {
                throw new InvalidPayloadException("Invalid encrypted payload: unsupported metadata.");
            }

            ValidateBase64Size(package.Salt, SaltSizeBytes, "salt");
            ValidateBase64Size(package.Nonce, NonceSizeBytes, "nonce");
            ValidateBase64Size(package.Tag, TagSizeBytes, "tag");

            ValidateBase64(package.Ciphertext, "ciphertext");
        }

        private static void ValidateBase64Size(string value, int expectedBytes, string name)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidPayloadException($"Invalid encrypted payload: {name} is missing.");
            }

            try
            {
                byte[] bytes = Convert.FromBase64String(value);
                if (bytes.Length != expectedBytes)
                {
                    throw new InvalidPayloadException($"Invalid encrypted payload: {name} has the wrong size.");
                }
            }
            catch (FormatException)
            {
                throw new InvalidPayloadException($"Invalid encrypted payload: {name} is not valid base64.");
            }
        }

        private static void ValidateBase64(string value, string name)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidPayloadException($"Invalid encrypted payload: {name} is missing.");
            }

            try
            {
                _ = Convert.FromBase64String(value);
            }
            catch (FormatException)
            {
                throw new InvalidPayloadException($"Invalid encrypted payload: {name} is not valid base64.");
            }
        }
    }

    private static class PayloadCodec
    {
        public static string Encode(EncryptedPackage package)
        {
            string json = JsonSerializer.Serialize(package, JsonOptions);
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            return PayloadPrefix + Base64UrlEncode(bytes);
        }

        public static EncryptedPackage Decode(string payload)
        {
            payload = payload.Trim();

            if (!payload.StartsWith(PayloadPrefix, StringComparison.Ordinal))
            {
                throw new InvalidPayloadException("Invalid encrypted payload: missing CRYPTORv1 prefix.");
            }

            string encoded = payload[PayloadPrefix.Length..];
            if (encoded.Length == 0)
            {
                throw new InvalidPayloadException("Invalid encrypted payload: no payload data found.");
            }

            try
            {
                byte[] jsonBytes = Base64UrlDecode(encoded);
                EncryptedPackage? package = JsonSerializer.Deserialize<EncryptedPackage>(jsonBytes, JsonOptions);

                return package ?? throw new InvalidPayloadException("Invalid encrypted payload: empty payload.");
            }
            catch (JsonException)
            {
                throw new InvalidPayloadException("Invalid encrypted payload: payload JSON is malformed.");
            }
            catch (FormatException)
            {
                throw new InvalidPayloadException("Invalid encrypted payload: payload is not valid base64url.");
            }
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        private static byte[] Base64UrlDecode(string value)
        {
            string base64 = value.Replace('-', '+').Replace('_', '/');
            int padding = base64.Length % 4;
            if (padding > 0)
            {
                base64 = base64.PadRight(base64.Length + 4 - padding, '=');
            }

            return Convert.FromBase64String(base64);
        }
    }

    private static class Clipboard
    {
        public static void CopyText(string text)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                RunClipboardCommand("clip.exe", string.Empty, text);
                return;
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                RunClipboardCommand("pbcopy", string.Empty, text);
                return;
            }

            if (CommandExists("wl-copy"))
            {
                RunClipboardCommand("wl-copy", string.Empty, text);
                return;
            }

            if (CommandExists("xclip"))
            {
                RunClipboardCommand("xclip", "-selection clipboard", text);
                return;
            }

            if (CommandExists("xsel"))
            {
                RunClipboardCommand("xsel", "--clipboard --input", text);
                return;
            }

            throw new ClipboardException("No supported clipboard tool was found. Save to a file or print to console instead.");
        }

        private static bool CommandExists(string command)
        {
            string probe = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "where" : "which";

            try
            {
                using Process process = Process.Start(new ProcessStartInfo
                {
                    FileName = probe,
                    ArgumentList = { command },
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                })!;

                process.WaitForExit();
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        private static void RunClipboardCommand(string fileName, string arguments, string text)
        {
            try
            {
                ProcessStartInfo startInfo = new()
                {
                    FileName = fileName,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                foreach (string argument in SplitArguments(arguments))
                {
                    startInfo.ArgumentList.Add(argument);
                }

                using Process process = Process.Start(startInfo)
                    ?? throw new ClipboardException($"Could not start clipboard tool '{fileName}'.");

                process.StandardInput.Write(text);
                process.StandardInput.Close();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    string error = process.StandardError.ReadToEnd().Trim();
                    throw new ClipboardException(string.IsNullOrWhiteSpace(error)
                        ? $"Clipboard tool '{fileName}' failed."
                        : $"Clipboard tool '{fileName}' failed: {error}");
                }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                throw new ClipboardException("No supported clipboard tool was found. Save to a file or print to console instead.");
            }
        }

        private static IEnumerable<string> SplitArguments(string arguments)
        {
            return arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
    }
}
