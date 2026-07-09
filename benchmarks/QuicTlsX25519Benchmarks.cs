// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the managed X25519 key-agreement helper used by the TLS key schedule.
/// </summary>
[MemoryDiagnoser]
public class QuicTlsX25519Benchmarks
{
    private static readonly byte[] AlicePrivateKey = Convert.FromHexString(
        "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A");

    private static readonly byte[] BobPrivateKey = Convert.FromHexString(
        "5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB");

    private static readonly byte[] BobPublicKey = Convert.FromHexString(
        "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F");

    private byte[] alicePublicKey = [];
    private byte[] bobPublicKey = [];
    private byte[] sharedSecret = [];

    /// <summary>
    /// Allocates reusable result buffers for RFC 7748 test-vector operations.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        alicePublicKey = new byte[QuicTlsX25519.KeyLength];
        bobPublicKey = new byte[QuicTlsX25519.KeyLength];
        sharedSecret = new byte[QuicTlsX25519.KeyLength];
    }

    /// <summary>
    /// Measures public-key derivation from a fixed RFC 7748 private scalar.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int DerivePublicKey()
    {
        return QuicTlsX25519.TryGetPublicKey(AlicePrivateKey, alicePublicKey)
            ? alicePublicKey[0] ^ alicePublicKey[^1]
            : -1;
    }

    /// <summary>
    /// Measures shared-secret derivation from fixed RFC 7748 peer keys.
    /// </summary>
    [Benchmark]
    public int DeriveSharedSecret()
    {
        return QuicTlsX25519.TryDeriveSharedSecret(AlicePrivateKey, BobPublicKey, sharedSecret)
            ? sharedSecret[0] ^ sharedSecret[^1]
            : -1;
    }

    /// <summary>
    /// Measures both sides of the RFC 7748 Diffie-Hellman exchange.
    /// </summary>
    [Benchmark]
    public int DeriveFullExchange()
    {
        if (!QuicTlsX25519.TryGetPublicKey(AlicePrivateKey, alicePublicKey)
            || !QuicTlsX25519.TryGetPublicKey(BobPrivateKey, bobPublicKey)
            || !QuicTlsX25519.TryDeriveSharedSecret(AlicePrivateKey, bobPublicKey, sharedSecret))
        {
            return -1;
        }

        return alicePublicKey[0] ^ bobPublicKey[^1] ^ sharedSecret[0] ^ sharedSecret[^1];
    }
}
