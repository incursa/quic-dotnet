// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Quic;

namespace Incursa.Quic.InteropHarness;

internal static class InteropHarnessSslKeyLogWriter
{
    private static readonly object FileWriteGate = new();

    public static Action<QuicTlsKeyLogSecret>? CreateObserver(string? outputPath)
    {
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            return null;
        }

        return secret =>
        {
            _ = TryAppend(outputPath, secret, out _);
        };
    }

    public static bool TryAppend(
        string outputPath,
        QuicTlsKeyLogSecret secret,
        out string? errorMessage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        errorMessage = null;

        try
        {
            string? directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            lock (FileWriteGate)
            {
                File.AppendAllText(outputPath, FormatLine(secret) + Environment.NewLine);
            }

            return true;
        }
        catch (Exception ex)
            when (ex is IOException
                or UnauthorizedAccessException
                or ArgumentException
                or NotSupportedException
                or PathTooLongException)
        {
            errorMessage = $"interop harness: failed to append SSLKEYLOGFILE output to '{outputPath}': {ex.Message}";
            return false;
        }
    }

    public static string FormatLine(QuicTlsKeyLogSecret secret)
    {
        return string.Join(
            ' ',
            secret.Label,
            Convert.ToHexString(secret.ClientRandom.Span).ToLowerInvariant(),
            Convert.ToHexString(secret.Secret.Span).ToLowerInvariant());
    }
}
