namespace Incursa.Quic;

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
