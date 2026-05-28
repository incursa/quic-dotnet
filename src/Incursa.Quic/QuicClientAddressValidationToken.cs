// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Threading;

namespace Incursa.Quic;

internal enum QuicAddressValidationTokenSource
{
    NewToken,
    Retry,
}

internal sealed class QuicClientAddressValidationToken
{
    private readonly byte[] token;
    private readonly IPEndPoint remoteEndPoint;
    private readonly uint version;
    private int consumed;

    private QuicClientAddressValidationToken(
        ReadOnlySpan<byte> token,
        IPEndPoint remoteEndPoint,
        uint version)
    {
        this.token = token.ToArray();
        this.remoteEndPoint = new IPEndPoint(remoteEndPoint.Address, remoteEndPoint.Port);
        this.version = version;
    }

    internal static bool TryCreate(
        ReadOnlySpan<byte> token,
        IPEndPoint? remoteEndPoint,
        uint version,
        QuicAddressValidationTokenSource source,
        out QuicClientAddressValidationToken? addressValidationToken)
    {
        addressValidationToken = null;

        if (token.IsEmpty
            || remoteEndPoint is null
            || version == 0
            || source != QuicAddressValidationTokenSource.NewToken)
        {
            return false;
        }

        addressValidationToken = new QuicClientAddressValidationToken(token, remoteEndPoint, version);
        return true;
    }

    internal bool TryConsume(
        IPEndPoint? candidateRemoteEndPoint,
        uint candidateVersion,
        out ReadOnlyMemory<byte> token)
    {
        token = default;

        if (candidateRemoteEndPoint is null
            || candidateVersion != version
            || !candidateRemoteEndPoint.Address.Equals(remoteEndPoint.Address)
            || candidateRemoteEndPoint.Port != remoteEndPoint.Port
            || Interlocked.CompareExchange(ref consumed, 1, 0) != 0)
        {
            return false;
        }

        token = this.token.ToArray();
        return true;
    }
}
