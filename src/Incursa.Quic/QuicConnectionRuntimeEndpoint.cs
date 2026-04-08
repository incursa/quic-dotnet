using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Owns the endpoint-side ingress pipeline, route registries, and handoff into the sharded connection runtime host.
/// </summary>
internal sealed class QuicConnectionRuntimeEndpoint : IAsyncDisposable, IDisposable
{
    private readonly IMonotonicClock clock;
    private readonly QuicConnectionRuntimeHost host;
    private readonly ConcurrentDictionary<QuicConnectionHandle, byte> registeredHandles = new();
    private readonly ConcurrentDictionary<QuicConnectionHandle, QuicConnectionPathIdentity> pathByHandle = new();
    private readonly ConcurrentDictionary<QuicConnectionHandle, ConcurrentDictionary<QuicConnectionIdKey, byte>> routeIdsByHandle = new();
    private readonly ConcurrentDictionary<byte, ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionHandle>> routesByLength = new();
    private readonly ConcurrentDictionary<QuicConnectionHandle, ConcurrentDictionary<ulong, byte>> statelessResetTokenIdsByHandle = new();
    private readonly ConcurrentDictionary<ulong, QuicConnectionStatelessResetBinding> statelessResetBindingsByConnectionId = new();

    public QuicConnectionRuntimeEndpoint(int shardCount, IMonotonicClock? clock = null)
    {
        if (shardCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(shardCount));
        }

        this.clock = clock ?? new MonotonicClock();
        host = new QuicConnectionRuntimeHost(shardCount, this.clock);
    }

    public int ShardCount => host.ShardCount;

    public QuicConnectionRuntimeHost Host => host;

    public QuicConnectionHandle AllocateConnectionHandle()
    {
        return host.AllocateConnectionHandle();
    }

    public int GetShardIndex(QuicConnectionHandle handle)
    {
        return host.GetShardIndex(handle);
    }

    public bool TryRegisterConnection(QuicConnectionHandle handle, QuicConnectionRuntime runtime)
    {
        if (!host.TryRegisterConnection(handle, runtime))
        {
            return false;
        }

        if (!registeredHandles.TryAdd(handle, 0))
        {
            host.TryUnregisterConnection(handle);
            return false;
        }

        return true;
    }

    public bool TryUnregisterConnection(QuicConnectionHandle handle)
    {
        if (!registeredHandles.ContainsKey(handle))
        {
            return false;
        }

        if (!host.TryUnregisterConnection(handle))
        {
            return false;
        }

        registeredHandles.TryRemove(handle, out _);
        pathByHandle.TryRemove(handle, out _);

        if (routeIdsByHandle.TryRemove(handle, out ConcurrentDictionary<QuicConnectionIdKey, byte>? routeIds))
        {
            foreach (QuicConnectionIdKey routeId in routeIds.Keys)
            {
                TryRemoveRoute(handle, routeId);
            }
        }

        if (statelessResetTokenIdsByHandle.TryRemove(handle, out ConcurrentDictionary<ulong, byte>? tokenIds))
        {
            foreach (ulong connectionId in tokenIds.Keys)
            {
                statelessResetBindingsByConnectionId.TryRemove(connectionId, out _);
            }
        }

        return true;
    }

    public bool TryRegisterConnectionId(QuicConnectionHandle handle, ReadOnlySpan<byte> connectionId)
    {
        if (!registeredHandles.ContainsKey(handle)
            || !QuicConnectionIdKey.TryCreate(connectionId, out QuicConnectionIdKey routeId))
        {
            return false;
        }

        ConcurrentDictionary<QuicConnectionIdKey, byte> routeIds = routeIdsByHandle.GetOrAdd(
            handle,
            static _ => new ConcurrentDictionary<QuicConnectionIdKey, byte>());

        if (!routeIds.TryAdd(routeId, 0))
        {
            return false;
        }

        ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionHandle> bucket = routesByLength.GetOrAdd(
            routeId.Length,
            static _ => new ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionHandle>());

        if (!bucket.TryAdd(routeId, handle))
        {
            routeIds.TryRemove(routeId, out _);
            if (routeIds.IsEmpty)
            {
                routeIdsByHandle.TryRemove(handle, out _);
            }

            return false;
        }

        return true;
    }

    public bool TryRetireConnectionId(QuicConnectionHandle handle, ReadOnlySpan<byte> connectionId)
    {
        if (!registeredHandles.ContainsKey(handle)
            || !QuicConnectionIdKey.TryCreate(connectionId, out QuicConnectionIdKey routeId))
        {
            return false;
        }

        if (!routeIdsByHandle.TryGetValue(handle, out ConcurrentDictionary<QuicConnectionIdKey, byte>? routeIds)
            || !routeIds.TryRemove(routeId, out _))
        {
            return false;
        }

        if (!TryRemoveRoute(handle, routeId))
        {
            routeIds.TryAdd(routeId, 0);
            return false;
        }

        if (routeIds.IsEmpty)
        {
            routeIdsByHandle.TryRemove(handle, out _);
        }

        return true;
    }

    public bool TryUpdateEndpointBinding(QuicConnectionHandle handle, QuicConnectionPathIdentity pathIdentity)
    {
        if (!registeredHandles.ContainsKey(handle))
        {
            return false;
        }

        pathByHandle[handle] = pathIdentity;

        if (statelessResetTokenIdsByHandle.TryGetValue(handle, out ConcurrentDictionary<ulong, byte>? tokenIds))
        {
            foreach (ulong connectionId in tokenIds.Keys)
            {
                if (statelessResetBindingsByConnectionId.TryGetValue(connectionId, out QuicConnectionStatelessResetBinding? binding))
                {
                    statelessResetBindingsByConnectionId[connectionId] = binding with
                    {
                        RemoteAddress = pathIdentity.RemoteAddress,
                    };
                }
            }
        }

        return true;
    }

    public bool TryRegisterStatelessResetToken(QuicConnectionHandle handle, ulong connectionId, ReadOnlySpan<byte> token)
    {
        if (!registeredHandles.ContainsKey(handle)
            || token.Length != QuicStatelessReset.StatelessResetTokenLength
            || !pathByHandle.TryGetValue(handle, out QuicConnectionPathIdentity pathIdentity))
        {
            return false;
        }

        ConcurrentDictionary<ulong, byte> tokenIds = statelessResetTokenIdsByHandle.GetOrAdd(
            handle,
            static _ => new ConcurrentDictionary<ulong, byte>());

        if (!tokenIds.TryAdd(connectionId, 0))
        {
            return false;
        }

        if (!statelessResetBindingsByConnectionId.TryAdd(
            connectionId,
            new QuicConnectionStatelessResetBinding(handle, pathIdentity.RemoteAddress, token.ToArray())))
        {
            tokenIds.TryRemove(connectionId, out _);
            if (tokenIds.IsEmpty)
            {
                statelessResetTokenIdsByHandle.TryRemove(handle, out _);
            }

            return false;
        }

        return true;
    }

    public bool TryRetireStatelessResetToken(QuicConnectionHandle handle, ulong connectionId)
    {
        if (!registeredHandles.ContainsKey(handle)
            || !statelessResetTokenIdsByHandle.TryGetValue(handle, out ConcurrentDictionary<ulong, byte>? tokenIds)
            || !tokenIds.TryRemove(connectionId, out _))
        {
            return false;
        }

        statelessResetBindingsByConnectionId.TryRemove(connectionId, out _);

        if (tokenIds.IsEmpty)
        {
            statelessResetTokenIdsByHandle.TryRemove(handle, out _);
        }

        return true;
    }

    public QuicConnectionIngressResult ReceiveDatagram(ReadOnlyMemory<byte> datagram, QuicConnectionPathIdentity pathIdentity)
    {
        if (datagram.IsEmpty)
        {
            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.Malformed,
                QuicConnectionEndpointHandlingKind.None,
                null);
        }

        ReadOnlySpan<byte> packet = datagram.Span;

        if (!QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm))
        {
            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.Malformed,
                QuicConnectionEndpointHandlingKind.None,
                null);
        }

        if (headerForm == QuicHeaderForm.Short)
        {
            return ReceiveShortHeaderDatagram(datagram, pathIdentity, packet);
        }

        if (QuicPacketParser.TryParseVersionNegotiation(packet, out _))
        {
            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.EndpointHandling,
                QuicConnectionEndpointHandlingKind.VersionNegotiation,
                null);
        }

        if (!QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket longHeader))
        {
            if (TryDispatchStatelessReset(datagram, pathIdentity, out QuicConnectionIngressResult parseFailureResetResult))
            {
                return parseFailureResetResult;
            }

            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.Malformed,
                QuicConnectionEndpointHandlingKind.None,
                null);
        }

        if (longHeader.IsVersionNegotiation)
        {
            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.Malformed,
                QuicConnectionEndpointHandlingKind.None,
                null);
        }

        if (longHeader.Version == 1 && longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.Retry)
        {
            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.EndpointHandling,
                QuicConnectionEndpointHandlingKind.Retry,
                null);
        }

        if (TryLookupExactRoute(longHeader.DestinationConnectionId, out QuicConnectionHandle routedHandle))
        {
            if (TryPostPacketReceived(routedHandle, datagram, pathIdentity))
            {
                return new QuicConnectionIngressResult(
                    QuicConnectionIngressDisposition.RoutedToConnection,
                    QuicConnectionEndpointHandlingKind.None,
                    routedHandle);
            }

            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.Unroutable,
                QuicConnectionEndpointHandlingKind.None,
                null);
        }

        if (TryDispatchStatelessReset(datagram, pathIdentity, out QuicConnectionIngressResult routeMissResetResult))
        {
            return routeMissResetResult;
        }

        return new QuicConnectionIngressResult(
            QuicConnectionIngressDisposition.Unroutable,
            QuicConnectionEndpointHandlingKind.None,
            null);
    }

    public Task RunAsync(
        Action<QuicConnectionHandle, int, QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionHandle, int, QuicConnectionEffect>? effectObserver = null,
        CancellationToken cancellationToken = default)
    {
        return host.RunAsync(
            transitionObserver,
            (handle, shardIndex, effect) =>
            {
                TryApplyEffect(handle, effect);
                effectObserver?.Invoke(handle, shardIndex, effect);
            },
            cancellationToken);
    }

    public bool TryApplyEffect(QuicConnectionHandle handle, QuicConnectionEffect effect)
    {
        ArgumentNullException.ThrowIfNull(effect);

        return effect switch
        {
            QuicConnectionPromoteActivePathEffect promoteActivePathEffect
                => TryUpdateEndpointBinding(handle, promoteActivePathEffect.PathIdentity),
            QuicConnectionUpdateEndpointBindingsEffect updateEndpointBindingsEffect
                => TryUpdateEndpointBinding(handle, updateEndpointBindingsEffect.PathIdentity),
            QuicConnectionRegisterStatelessResetTokenEffect registerStatelessResetTokenEffect
                => TryRegisterStatelessResetToken(handle, registerStatelessResetTokenEffect.ConnectionId, registerStatelessResetTokenEffect.Token.Span),
            QuicConnectionRetireStatelessResetTokenEffect retireStatelessResetTokenEffect
                => TryRetireStatelessResetToken(handle, retireStatelessResetTokenEffect.ConnectionId),
            QuicConnectionDiscardConnectionStateEffect => TryUnregisterConnection(handle),
            _ => false,
        };
    }

    public async ValueTask DisposeAsync()
    {
        await host.DisposeAsync().ConfigureAwait(false);

        registeredHandles.Clear();
        pathByHandle.Clear();
        routeIdsByHandle.Clear();
        routesByLength.Clear();
        statelessResetTokenIdsByHandle.Clear();
        statelessResetBindingsByConnectionId.Clear();
    }

    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    private QuicConnectionIngressResult ReceiveShortHeaderDatagram(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packet)
    {
        if (QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket shortHeader))
        {
            if (TryLookupRouteByPrefix(shortHeader.Remainder, out QuicConnectionHandle routedHandle))
            {
                if (TryPostPacketReceived(routedHandle, datagram, pathIdentity))
                {
                    return new QuicConnectionIngressResult(
                        QuicConnectionIngressDisposition.RoutedToConnection,
                        QuicConnectionEndpointHandlingKind.None,
                        routedHandle);
                }

                return new QuicConnectionIngressResult(
                    QuicConnectionIngressDisposition.Unroutable,
                    QuicConnectionEndpointHandlingKind.None,
                    null);
            }

            if (TryDispatchStatelessReset(datagram, pathIdentity, out QuicConnectionIngressResult statelessResetResult))
            {
                return statelessResetResult;
            }

            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.Unroutable,
                QuicConnectionEndpointHandlingKind.None,
                null);
        }

        if (TryDispatchStatelessReset(datagram, pathIdentity, out QuicConnectionIngressResult shortHeaderResetResult))
        {
            return shortHeaderResetResult;
        }

        return new QuicConnectionIngressResult(
            QuicConnectionIngressDisposition.Malformed,
            QuicConnectionEndpointHandlingKind.None,
            null);
    }

    private bool TryLookupExactRoute(ReadOnlySpan<byte> connectionId, out QuicConnectionHandle handle)
    {
        handle = default;

        if (!QuicConnectionIdKey.TryCreate(connectionId, out QuicConnectionIdKey routeId))
        {
            return false;
        }

        return TryLookupRoute(routeId, out handle);
    }

    private bool TryLookupRouteByPrefix(ReadOnlySpan<byte> connectionIdRemainder, out QuicConnectionHandle handle)
    {
        handle = default;

        int maximumCandidateLength = Math.Min(connectionIdRemainder.Length, QuicConnectionIdKey.MaximumLength);
        for (int candidateLength = maximumCandidateLength; candidateLength >= 0; candidateLength--)
        {
            if (!routesByLength.TryGetValue((byte)candidateLength, out ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionHandle>? bucket))
            {
                continue;
            }

            if (!QuicConnectionIdKey.TryCreate(connectionIdRemainder[..candidateLength], out QuicConnectionIdKey routeId))
            {
                continue;
            }

            if (bucket.TryGetValue(routeId, out handle))
            {
                return true;
            }
        }

        return false;
    }

    private bool TryLookupRoute(QuicConnectionIdKey routeId, out QuicConnectionHandle handle)
    {
        if (!routesByLength.TryGetValue(routeId.Length, out ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionHandle>? bucket))
        {
            handle = default;
            return false;
        }

        return bucket.TryGetValue(routeId, out handle);
    }

    private bool TryRemoveRoute(QuicConnectionHandle handle, QuicConnectionIdKey routeId)
    {
        if (!routesByLength.TryGetValue(routeId.Length, out ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionHandle>? bucket)
            || !bucket.TryGetValue(routeId, out QuicConnectionHandle routeHandle)
            || routeHandle != handle
            || !bucket.TryRemove(routeId, out _))
        {
            return false;
        }

        if (bucket.IsEmpty)
        {
            routesByLength.TryRemove(routeId.Length, out _);
        }

        return true;
    }

    private bool TryPostPacketReceived(QuicConnectionHandle handle, ReadOnlyMemory<byte> datagram, QuicConnectionPathIdentity pathIdentity)
    {
        return host.TryPostEvent(handle, new QuicConnectionPacketReceivedEvent(clock.Ticks, pathIdentity, datagram));
    }

    private bool TryDispatchStatelessReset(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionIngressResult result)
    {
        if (!QuicStatelessReset.IsPotentialStatelessReset(datagram.Span)
            || !QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram.Span, out ReadOnlySpan<byte> trailingToken))
        {
            result = default;
            return false;
        }

        foreach (QuicConnectionStatelessResetBinding binding in statelessResetBindingsByConnectionId.Values)
        {
            if (!pathByHandle.TryGetValue(binding.Handle, out QuicConnectionPathIdentity currentPathIdentity)
                || !string.Equals(currentPathIdentity.RemoteAddress, pathIdentity.RemoteAddress, StringComparison.Ordinal)
                || !CryptographicOperations.FixedTimeEquals(trailingToken, binding.Token))
            {
                continue;
            }

            if (!host.TryPostEvent(binding.Handle, new QuicConnectionStatelessResetMatchedEvent(clock.Ticks, pathIdentity)))
            {
                result = default;
                return false;
            }

            result = new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.EndpointHandling,
                QuicConnectionEndpointHandlingKind.StatelessReset,
                binding.Handle);
            return true;
        }

        result = default;
        return false;
    }
}
