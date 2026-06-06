// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: These labels match the TLS key-log format used by debugger tooling, and the payload is
// copied out of caller spans so later logging does not depend on borrowed memory.
// SEE: QuicTlsTransport
internal readonly record struct QuicTlsKeyLogSecret
{
    public const string ClientHandshakeTrafficSecretLabel = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    public const string ServerHandshakeTrafficSecretLabel = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    public const string ClientApplicationTrafficSecretLabel = "CLIENT_TRAFFIC_SECRET_0";
    public const string ServerApplicationTrafficSecretLabel = "SERVER_TRAFFIC_SECRET_0";

    public QuicTlsKeyLogSecret(
        string label,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);
        if (clientRandom.IsEmpty)
        {
            throw new ArgumentException("The TLS client random must not be empty.", nameof(clientRandom));
        }

        if (secret.IsEmpty)
        {
            throw new ArgumentException("The TLS traffic secret must not be empty.", nameof(secret));
        }

        Label = label;
        ClientRandom = clientRandom.ToArray();
        Secret = secret.ToArray();
    }

    public string Label { get; }

    public ReadOnlyMemory<byte> ClientRandom { get; }

    public ReadOnlyMemory<byte> Secret { get; }
}
