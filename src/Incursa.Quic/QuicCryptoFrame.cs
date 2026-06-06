// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: CRYPTO frames are represented as a ref struct because they borrow packet payload bytes
// during handshake parsing and should not be copied into heap-backed wrappers.
// SEE: QuicTlsTranscriptProgress
/// <summary>
/// A parsed or constructed CRYPTO frame.
/// </summary>
internal readonly ref struct QuicCryptoFrame
{
    private readonly ulong offset;
    private readonly ReadOnlySpan<byte> cryptoData;

    /// <summary>
    /// Initializes a CRYPTO frame view.
    /// </summary>
    internal QuicCryptoFrame(ulong offset, ReadOnlySpan<byte> cryptoData)
    {
        this.offset = offset;
        this.cryptoData = cryptoData;
    }

    /// <summary>
    /// Gets the crypto stream offset.
    /// </summary>
    internal ulong Offset => offset;

    /// <summary>
    /// Gets the CRYPTO data bytes.
    /// </summary>
    internal ReadOnlySpan<byte> CryptoData => cryptoData;
}
