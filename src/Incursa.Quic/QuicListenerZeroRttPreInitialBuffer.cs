// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;

namespace Incursa.Quic;

internal readonly record struct QuicListenerBufferedZeroRttDatagram(
    ReadOnlyMemory<byte> Datagram,
    QuicConnectionPathIdentity PathIdentity);

internal sealed class QuicListenerZeroRttPreInitialBuffer
{
    // CONTEXT: pre-Initial 0-RTT buffering stays per DCID and bounded
    // SEE: code:src/Incursa.Quic/QuicListenerZeroRttPreInitialBuffer.cs#TryBuffer
    // SEE: code:src/Incursa.Quic/QuicListenerZeroRttPreInitialBuffer.cs#Drain
    // The listener parks at most a small number of 0-RTT datagrams per
    // destination connection ID until the matching Initial arrives. The
    // datagrams are copied to owned storage because the receive buffer is
    // transient and the buffered packets may outlive the ingress loop.
    private readonly int maximumDatagramsPerConnection;
    private readonly ConcurrentDictionary<QuicConnectionIdKey, ConnectionBuffer> buffersByDestinationConnectionId = new();

    internal QuicListenerZeroRttPreInitialBuffer(int maximumDatagramsPerConnection)
    {
        if (maximumDatagramsPerConnection < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumDatagramsPerConnection));
        }

        this.maximumDatagramsPerConnection = maximumDatagramsPerConnection;
    }

    internal bool TryBuffer(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity)
    {
        if (maximumDatagramsPerConnection == 0
            || datagram.IsEmpty
            || !QuicConnectionIdKey.TryCreate(initialDestinationConnectionId, out QuicConnectionIdKey key))
        {
            return false;
        }

        ConnectionBuffer buffer = buffersByDestinationConnectionId.GetOrAdd(
            key,
            _ => new ConnectionBuffer(maximumDatagramsPerConnection));

        return buffer.TryAdd(new QuicListenerBufferedZeroRttDatagram(datagram.ToArray(), pathIdentity));
    }

    internal QuicListenerBufferedZeroRttDatagram[] Drain(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        if (!QuicConnectionIdKey.TryCreate(initialDestinationConnectionId, out QuicConnectionIdKey key)
            || !buffersByDestinationConnectionId.TryRemove(key, out ConnectionBuffer? buffer))
        {
            return [];
        }

        return buffer.Drain();
    }

    internal int CountForConnectionId(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        return QuicConnectionIdKey.TryCreate(initialDestinationConnectionId, out QuicConnectionIdKey key)
            && buffersByDestinationConnectionId.TryGetValue(key, out ConnectionBuffer? buffer)
            ? buffer.Count
            : 0;
    }

    private sealed class ConnectionBuffer
    {
        private readonly object gate = new();
        private readonly List<QuicListenerBufferedZeroRttDatagram> datagrams = [];
        private readonly int maximumDatagrams;

        internal ConnectionBuffer(int maximumDatagrams)
        {
            this.maximumDatagrams = maximumDatagrams;
        }

        internal int Count
        {
            get
            {
                lock (gate)
                {
                    return datagrams.Count;
                }
            }
        }

        internal bool TryAdd(QuicListenerBufferedZeroRttDatagram datagram)
        {
            lock (gate)
            {
                if (datagrams.Count >= maximumDatagrams)
                {
                    return false;
                }

                datagrams.Add(datagram);
                return true;
            }
        }

        internal QuicListenerBufferedZeroRttDatagram[] Drain()
        {
            lock (gate)
            {
                if (datagrams.Count == 0)
                {
                    return [];
                }

                QuicListenerBufferedZeroRttDatagram[] drained = [.. datagrams];
                datagrams.Clear();
                return drained;
            }
        }
    }
}
