// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;

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
    private readonly ConcurrentDictionary<QuicConnectionHandle, ConcurrentDictionary<QuicConnectionIdKey, ulong>> statelessResetConnectionIdsByRouteIdByHandle = new();
    private readonly ConcurrentDictionary<QuicConnectionHandle, ConcurrentDictionary<ulong, byte>> statelessResetTokenIdsByHandle = new();
    private readonly ConcurrentDictionary<QuicConnectionStatelessResetMatchKey, QuicConnectionStatelessResetBinding> statelessResetBindingsByMatchKey = new();
    private readonly ConcurrentDictionary<ulong, QuicConnectionStatelessResetBinding> statelessResetBindingsByConnectionId = new();
    private readonly ConcurrentDictionary<byte, ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionStatelessResetBinding>> retainedStatelessResetBindingsByRouteLength = new();
    private readonly ConcurrentDictionary<QuicConnectionHandle, QuicConnectionVersionProfile> versionProfilesByHandle = new();
    private readonly ConcurrentDictionary<QuicConnectionHandle, ulong> maxUdpPayloadSizeByHandle = new();
    private readonly ConcurrentDictionary<string, int> statelessResetEmissionCountsByRemoteAddress = new(StringComparer.Ordinal);
    private readonly int maximumStatelessResetEmissionsPerRemoteAddress;

    public QuicConnectionRuntimeEndpoint(
        int shardCount,
        IMonotonicClock? clock = null,
        int maximumStatelessResetEmissionsPerRemoteAddress = 1)
    {
        if (shardCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(shardCount));
        }

        if (maximumStatelessResetEmissionsPerRemoteAddress < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumStatelessResetEmissionsPerRemoteAddress));
        }

        this.clock = clock ?? new MonotonicClock();
        host = new QuicConnectionRuntimeHost(shardCount, this.clock);
        this.maximumStatelessResetEmissionsPerRemoteAddress = maximumStatelessResetEmissionsPerRemoteAddress;
    }

    public int ShardCount => host.ShardCount;

    public QuicConnectionRuntimeHost Host => host;

    // CONTEXT: The endpoint keeps routing, CID ownership, and retained stateless-reset bindings in
    // separate maps because packet routing, CID retirement, and late reset handling each use a different
    // key shape. The split is intentional so unregistering a handle can still preserve a retained
    // stateless-reset route when requested.
    // SEE: code:src/Incursa.Quic/QuicConnectionRuntimeEndpoint.cs#TryRegisterConnectionId
    // SEE: code:src/Incursa.Quic/QuicConnectionRuntimeEndpoint.cs#TryRetireConnectionId
    // SEE: code:src/Incursa.Quic/QuicConnectionRuntimeEndpoint.cs#RetainStatelessResetRoute
    internal ConcurrentDictionary<QuicConnectionHandle, ConcurrentDictionary<QuicConnectionIdKey, byte>> RouteIdsByHandle => routeIdsByHandle;

    internal ConcurrentDictionary<byte, ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionHandle>> RoutesByLength => routesByLength;

    internal ConcurrentDictionary<QuicConnectionHandle, ConcurrentDictionary<QuicConnectionIdKey, ulong>> StatelessResetConnectionIdsByRouteIdByHandle => statelessResetConnectionIdsByRouteIdByHandle;

    internal ConcurrentDictionary<QuicConnectionHandle, ConcurrentDictionary<ulong, byte>> StatelessResetTokenIdsByHandle => statelessResetTokenIdsByHandle;

    internal ConcurrentDictionary<QuicConnectionStatelessResetMatchKey, QuicConnectionStatelessResetBinding> StatelessResetBindingsByMatchKey => statelessResetBindingsByMatchKey;

    internal ConcurrentDictionary<ulong, QuicConnectionStatelessResetBinding> StatelessResetBindingsByConnectionId => statelessResetBindingsByConnectionId;

    internal ConcurrentDictionary<byte, ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionStatelessResetBinding>> RetainedStatelessResetBindingsByRouteLength => retainedStatelessResetBindingsByRouteLength;

    internal void SetVersionProfileForTests(QuicConnectionHandle handle, QuicConnectionVersionProfile versionProfile)
    {
        versionProfilesByHandle[handle] = versionProfile;
    }

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

        versionProfilesByHandle[handle] = runtime.VersionProfile;
        maxUdpPayloadSizeByHandle[handle] = QuicTransportParameters.DefaultMaxUdpPayloadSize;

        return true;
    }

    public bool TryUnregisterConnection(QuicConnectionHandle handle, bool preserveStatelessResetEmissionState = false)
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
        versionProfilesByHandle.TryRemove(handle, out _);
        maxUdpPayloadSizeByHandle.TryRemove(handle, out _);

        if (routeIdsByHandle.TryRemove(handle, out ConcurrentDictionary<QuicConnectionIdKey, byte>? routeIds))
        {
            foreach (QuicConnectionIdKey routeId in routeIds.Keys)
            {
                if (preserveStatelessResetEmissionState)
                {
                    RetainStatelessResetRoute(handle, routeId);
                }

                TryRemoveRoute(handle, routeId);
            }
        }

        statelessResetConnectionIdsByRouteIdByHandle.TryRemove(handle, out _);

        if (statelessResetTokenIdsByHandle.TryRemove(handle, out ConcurrentDictionary<ulong, byte>? tokenIds))
        {
            foreach (ulong connectionId in tokenIds.Keys)
            {
                TryRemoveStatelessResetBinding(connectionId, preserveStatelessResetEmissionState);
            }
        }

        return true;
    }

    private void RetainStatelessResetRoute(QuicConnectionHandle handle, QuicConnectionIdKey routeId)
    {
        if (routeId.Length == 0
            || !statelessResetConnectionIdsByRouteIdByHandle.TryGetValue(handle, out ConcurrentDictionary<QuicConnectionIdKey, ulong>? connectionIdsByRoute)
            || !connectionIdsByRoute.TryGetValue(routeId, out ulong connectionId)
            || !statelessResetBindingsByConnectionId.TryGetValue(connectionId, out QuicConnectionStatelessResetBinding? binding)
            || binding.Handle != handle)
        {
            return;
        }

        ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionStatelessResetBinding> retainedRoutes = retainedStatelessResetBindingsByRouteLength.GetOrAdd(
            routeId.Length,
            static _ => new ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionStatelessResetBinding>());
        retainedRoutes[routeId] = binding;
    }

    public bool TryRegisterConnectionId(
        QuicConnectionHandle handle,
        ReadOnlySpan<byte> connectionId,
        ulong? statelessResetConnectionId = null)
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

        if (statelessResetConnectionId.HasValue)
        {
            ConcurrentDictionary<QuicConnectionIdKey, ulong> statelessResetRouteIds = statelessResetConnectionIdsByRouteIdByHandle.GetOrAdd(
                handle,
                static _ => new ConcurrentDictionary<QuicConnectionIdKey, ulong>());

            if (!statelessResetRouteIds.TryAdd(routeId, statelessResetConnectionId.Value))
            {
                TryRemoveRoute(handle, routeId);
                routeIds.TryRemove(routeId, out _);
                if (routeIds.IsEmpty)
                {
                    routeIdsByHandle.TryRemove(handle, out _);
                }

                return false;
            }
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

        if (statelessResetConnectionIdsByRouteIdByHandle.TryGetValue(handle, out ConcurrentDictionary<QuicConnectionIdKey, ulong>? statelessResetRouteIds))
        {
            statelessResetRouteIds.TryRemove(routeId, out _);
            if (statelessResetRouteIds.IsEmpty)
            {
                statelessResetConnectionIdsByRouteIdByHandle.TryRemove(handle, out _);
            }
        }

        return true;
    }

    public bool TryUpdateEndpointBinding(QuicConnectionHandle handle, QuicConnectionPathIdentity pathIdentity)
    {
        if (!registeredHandles.ContainsKey(handle))
        {
            return false;
        }

        if (statelessResetTokenIdsByHandle.TryGetValue(handle, out ConcurrentDictionary<ulong, byte>? tokenIds))
        {
            foreach (ulong connectionId in tokenIds.Keys)
            {
                if (statelessResetBindingsByConnectionId.TryGetValue(connectionId, out QuicConnectionStatelessResetBinding? binding))
                {
                    if (!TryMoveStatelessResetBinding(connectionId, binding, pathIdentity))
                    {
                        return false;
                    }
                }
            }
        }

        pathByHandle[handle] = pathIdentity;
        return true;
    }

    public bool TryUpdateMaxUdpPayloadSize(QuicConnectionHandle handle, ulong maxUdpPayloadSize)
    {
        if (!registeredHandles.ContainsKey(handle)
            || maxUdpPayloadSize < QuicTransportParameters.MinimumMaxUdpPayloadSize)
        {
            return false;
        }

        maxUdpPayloadSizeByHandle[handle] = maxUdpPayloadSize;
        return true;
    }

    public bool TryRegisterStatelessResetToken(QuicConnectionHandle handle, ulong connectionId, ReadOnlySpan<byte> token)
    {
        if (!registeredHandles.ContainsKey(handle)
            || token.Length != QuicStatelessReset.StatelessResetTokenLength
            || !pathByHandle.TryGetValue(handle, out QuicConnectionPathIdentity pathIdentity)
            || !versionProfilesByHandle.TryGetValue(handle, out QuicConnectionVersionProfile versionProfile))
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

        byte[] tokenBuffer = token.ToArray();
        if (!QuicConnectionStatelessResetTokenKey.TryCreate(tokenBuffer, out QuicConnectionStatelessResetTokenKey tokenKey))
        {
            tokenIds.TryRemove(connectionId, out _);
            if (tokenIds.IsEmpty)
            {
                statelessResetTokenIdsByHandle.TryRemove(handle, out _);
            }

            return false;
        }

        QuicConnectionStatelessResetBinding binding = new(handle, connectionId, pathIdentity, tokenBuffer, versionProfile);
        QuicConnectionStatelessResetMatchKey matchKey = new(pathIdentity.RemoteAddress, tokenKey);
        if (!statelessResetBindingsByMatchKey.TryAdd(matchKey, binding))
        {
            tokenIds.TryRemove(connectionId, out _);
            if (tokenIds.IsEmpty)
            {
                statelessResetTokenIdsByHandle.TryRemove(handle, out _);
            }

            return false;
        }

        if (!statelessResetBindingsByConnectionId.TryAdd(connectionId, binding))
        {
            statelessResetBindingsByMatchKey.TryRemove(matchKey, out _);
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

        TryRemoveStatelessResetBinding(connectionId);

        if (tokenIds.IsEmpty)
        {
            statelessResetTokenIdsByHandle.TryRemove(handle, out _);
        }

        return true;
    }

    public QuicConnectionStatelessResetEmissionResult TryCreateStatelessResetDatagram(
        QuicConnectionHandle handle,
        ulong connectionId,
        int triggeringPacketLength,
        bool hasLoopPreventionState)
    {
        if (!statelessResetBindingsByConnectionId.TryGetValue(connectionId, out QuicConnectionStatelessResetBinding? binding)
            || binding.Handle != handle)
        {
            return new QuicConnectionStatelessResetEmissionResult(
                QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable,
                null,
                ReadOnlyMemory<byte>.Empty);
        }

        return TryCreateStatelessResetDatagram(
            binding,
            binding.PathIdentity,
            triggeringPacketLength,
            hasLoopPreventionState);
    }

    public QuicConnectionStatelessResetEmissionResult TryCreateStatelessResetDatagramForPacket(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        bool hasLoopPreventionState)
    {
        if (!TryLookupRetainedStatelessResetBinding(datagram.Span, pathIdentity, out QuicConnectionStatelessResetBinding? binding))
        {
            return new QuicConnectionStatelessResetEmissionResult(
                QuicConnectionStatelessResetEmissionDisposition.TokenUnavailable,
                null,
                ReadOnlyMemory<byte>.Empty);
        }

        if (IsKnownStatelessResetTrigger(datagram.Span, binding!.Token))
        {
            return new QuicConnectionStatelessResetEmissionResult(
                QuicConnectionStatelessResetEmissionDisposition.StatelessResetLoopSuppressed,
                pathIdentity,
                ReadOnlyMemory<byte>.Empty);
        }

        return TryCreateStatelessResetDatagram(
            binding,
            pathIdentity,
            datagram.Length,
            hasLoopPreventionState);
    }

    private QuicConnectionStatelessResetEmissionResult TryCreateStatelessResetDatagram(
        QuicConnectionStatelessResetBinding binding,
        QuicConnectionPathIdentity responsePathIdentity,
        int triggeringPacketLength,
        bool hasLoopPreventionState)
    {
        int datagramLength = Math.Max(QuicStatelessReset.MinimumDatagramLength, triggeringPacketLength - 1);
        if (!QuicStatelessReset.CanSendStatelessReset(triggeringPacketLength, datagramLength, hasLoopPreventionState))
        {
            return new QuicConnectionStatelessResetEmissionResult(
                QuicConnectionStatelessResetEmissionDisposition.LoopOrAmplificationPrevented,
                responsePathIdentity,
                ReadOnlyMemory<byte>.Empty);
        }

        if (!TryReserveStatelessResetEmission(responsePathIdentity.RemoteAddress))
        {
            return new QuicConnectionStatelessResetEmissionResult(
                QuicConnectionStatelessResetEmissionDisposition.RateLimited,
                responsePathIdentity,
                ReadOnlyMemory<byte>.Empty);
        }

        byte[] datagram = new byte[datagramLength];
        if (!QuicStatelessReset.TryFormatStatelessResetDatagram(
                binding.Token,
                binding.VersionProfile.SupportedVersions.Span,
                datagramLength,
                datagram,
                out int bytesWritten))
        {
            return new QuicConnectionStatelessResetEmissionResult(
                QuicConnectionStatelessResetEmissionDisposition.FormatFailed,
                responsePathIdentity,
                ReadOnlyMemory<byte>.Empty);
        }

        return new QuicConnectionStatelessResetEmissionResult(
            QuicConnectionStatelessResetEmissionDisposition.Emitted,
            responsePathIdentity,
            datagram.AsMemory(0, bytesWritten));
    }

    public QuicConnectionIngressResult ReceiveDatagram(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        QuicEcnCounts? ecnCounts = null,
        byte[]? ownedDatagramBuffer = null,
        QuicReceiveBufferOwnership ownedDatagramBufferOwnership = default)
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
            return ReceiveShortHeaderDatagram(
                datagram,
                pathIdentity,
                packet,
                ecnCounts,
                ownedDatagramBuffer,
                ownedDatagramBufferOwnership);
        }

        if (QuicPacketParser.TryParseVersionNegotiation(packet, out _))
        {
            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.EndpointHandling,
                QuicConnectionEndpointHandlingKind.VersionNegotiation,
                null);
        }

        if (!QuicPacketParser.TryParseLongHeader(packet, allowClearedFixedBit: true, out QuicLongHeaderPacket longHeader))
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

        if (QuicVersionNegotiation.IsSupportedTransportVersion(longHeader.Version)
            && QuicVersionNegotiation.TryGetLongHeaderPacketType(
                longHeader.Version,
                longHeader.LongPacketTypeBits,
                out QuicLongPacketType packetType)
            && packetType == QuicLongPacketType.Retry)
        {
            if (!longHeader.FixedBit)
            {
                return new QuicConnectionIngressResult(
                    QuicConnectionIngressDisposition.Malformed,
                    QuicConnectionEndpointHandlingKind.None,
                    null);
            }

            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.EndpointHandling,
                QuicConnectionEndpointHandlingKind.Retry,
                null);
        }

        if (QuicVersionNegotiation.TryGetLongHeaderPacketType(
                longHeader.Version,
                longHeader.LongPacketTypeBits,
                out QuicLongPacketType longPacketType)
            && longPacketType == QuicLongPacketType.Initial
            && datagram.Length < QuicVersionNegotiation.GetMinimumInitialDatagramPayloadSize(longHeader.Version))
        {
            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.Malformed,
                QuicConnectionEndpointHandlingKind.None,
                null);
        }

        if (TryLookupExactRoute(
            longHeader.DestinationConnectionId,
            pathIdentity,
            out QuicConnectionHandle routedHandle,
            out ulong? routedLocallyIssuedConnectionId))
        {
            if (ExceedsMaxUdpPayloadSize(routedHandle, datagram.Length))
            {
                return CreateDroppedIngressResult(routedHandle);
            }

            if (TryPostPacketReceived(
                    routedHandle,
                    datagram,
                    pathIdentity,
                    routedLocallyIssuedConnectionId,
                    ecnCounts,
                    ownedDatagramBuffer,
                    ownedDatagramBufferOwnership))
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

    internal bool TryGetRetainedVersionProfile(
        QuicConnectionHandle handle,
        out QuicConnectionVersionProfile versionProfile)
    {
        return versionProfilesByHandle.TryGetValue(handle, out versionProfile);
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
            QuicConnectionSendDatagramEffect => true,
            QuicConnectionPromoteActivePathEffect promoteActivePathEffect
                => TryUpdateEndpointBinding(handle, promoteActivePathEffect.PathIdentity),
            QuicConnectionUpdateEndpointBindingsEffect updateEndpointBindingsEffect
                => TryUpdateEndpointBinding(handle, updateEndpointBindingsEffect.PathIdentity),
            QuicConnectionRegisterConnectionIdRouteEffect registerConnectionIdRouteEffect
                => TryRegisterConnectionId(handle, registerConnectionIdRouteEffect.ConnectionIdBytes.Span, registerConnectionIdRouteEffect.ConnectionId),
            QuicConnectionRetireConnectionIdRouteEffect retireConnectionIdRouteEffect
                => TryRetireConnectionId(handle, retireConnectionIdRouteEffect.ConnectionIdBytes.Span),
            QuicConnectionRegisterStatelessResetTokenEffect registerStatelessResetTokenEffect
                => TryRegisterStatelessResetToken(handle, registerStatelessResetTokenEffect.ConnectionId, registerStatelessResetTokenEffect.Token.Span),
            QuicConnectionRetireStatelessResetTokenEffect retireStatelessResetTokenEffect
                => TryRetireStatelessResetToken(handle, retireStatelessResetTokenEffect.ConnectionId),
            QuicConnectionUpdateMaxUdpPayloadSizeEffect updateMaxUdpPayloadSizeEffect
                => TryUpdateMaxUdpPayloadSize(handle, updateMaxUdpPayloadSizeEffect.MaxUdpPayloadSize),
            QuicConnectionDiscardConnectionStateEffect discardConnectionStateEffect
                => TryUnregisterConnection(handle, discardConnectionStateEffect.TerminalState is not null),
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
        statelessResetConnectionIdsByRouteIdByHandle.Clear();
        statelessResetTokenIdsByHandle.Clear();
        statelessResetBindingsByMatchKey.Clear();
        statelessResetBindingsByConnectionId.Clear();
        retainedStatelessResetBindingsByRouteLength.Clear();
        versionProfilesByHandle.Clear();
        maxUdpPayloadSizeByHandle.Clear();
        statelessResetEmissionCountsByRemoteAddress.Clear();
    }

    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    private QuicConnectionIngressResult ReceiveShortHeaderDatagram(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> packet,
        QuicEcnCounts? ecnCounts,
        byte[]? ownedDatagramBuffer,
        QuicReceiveBufferOwnership ownedDatagramBufferOwnership)
    {
        if (packet.IsEmpty)
        {
            return new QuicConnectionIngressResult(
                QuicConnectionIngressDisposition.Malformed,
                QuicConnectionEndpointHandlingKind.None,
                null);
        }

        if ((packet[0] & QuicPacketHeaderBits.HeaderFormBitMask) == 0)
        {
            if (TryLookupRouteByPrefix(
                packet[1..],
                pathIdentity,
                out QuicConnectionHandle routedHandle,
                out ulong? routedLocallyIssuedConnectionId))
            {
                if (ExceedsMaxUdpPayloadSize(routedHandle, datagram.Length))
                {
                    return CreateDroppedIngressResult(routedHandle);
                }

                if (TryPostPacketReceived(
                        routedHandle,
                        datagram,
                        pathIdentity,
                        routedLocallyIssuedConnectionId,
                        ecnCounts,
                        ownedDatagramBuffer,
                        ownedDatagramBufferOwnership))
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

    private bool ExceedsMaxUdpPayloadSize(QuicConnectionHandle handle, int datagramLength)
    {
        ulong limit = maxUdpPayloadSizeByHandle.TryGetValue(handle, out ulong configuredLimit)
            ? configuredLimit
            : QuicTransportParameters.DefaultMaxUdpPayloadSize;

        return (ulong)datagramLength > limit;
    }

    private static QuicConnectionIngressResult CreateDroppedIngressResult(QuicConnectionHandle handle)
    {
        return new QuicConnectionIngressResult(
            QuicConnectionIngressDisposition.Dropped,
            QuicConnectionEndpointHandlingKind.None,
            handle);
    }

    private bool TryLookupExactRoute(
        ReadOnlySpan<byte> connectionId,
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionHandle handle,
        out ulong? routedLocallyIssuedConnectionId)
    {
        handle = default;
        routedLocallyIssuedConnectionId = null;

        if (!QuicConnectionIdKey.TryCreate(connectionId, out QuicConnectionIdKey routeId))
        {
            return false;
        }

        return TryLookupRoute(routeId, pathIdentity, out handle, out routedLocallyIssuedConnectionId);
    }

    private bool TryLookupRouteByPrefix(
        ReadOnlySpan<byte> connectionIdRemainder,
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionHandle handle,
        out ulong? routedLocallyIssuedConnectionId)
    {
        handle = default;
        routedLocallyIssuedConnectionId = null;

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

            if (bucket.TryGetValue(routeId, out handle)
                && IsRouteAddressMatch(routeId, handle, pathIdentity))
            {
                routedLocallyIssuedConnectionId = TryGetRoutedLocallyIssuedConnectionId(handle, routeId, out ulong connectionId)
                    ? connectionId
                    : null;
                return true;
            }
        }

        return false;
    }

    private bool TryLookupRoute(
        QuicConnectionIdKey routeId,
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionHandle handle,
        out ulong? routedLocallyIssuedConnectionId)
    {
        routedLocallyIssuedConnectionId = null;
        if (!routesByLength.TryGetValue(routeId.Length, out ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionHandle>? bucket))
        {
            handle = default;
            return false;
        }

        if (!bucket.TryGetValue(routeId, out handle)
            || !IsRouteAddressMatch(routeId, handle, pathIdentity))
        {
            handle = default;
            return false;
        }

        routedLocallyIssuedConnectionId = TryGetRoutedLocallyIssuedConnectionId(handle, routeId, out ulong connectionId)
            ? connectionId
            : null;
        return true;
    }

    private bool IsRouteAddressMatch(
        QuicConnectionIdKey routeId,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity)
    {
        return routeId.Length != 0
            || (pathByHandle.TryGetValue(handle, out QuicConnectionPathIdentity registeredPathIdentity)
                && IsSameLocalEndpoint(registeredPathIdentity, pathIdentity));
    }

    private bool TryGetRoutedLocallyIssuedConnectionId(
        QuicConnectionHandle handle,
        QuicConnectionIdKey routeId,
        out ulong connectionId)
    {
        connectionId = default;
        return statelessResetConnectionIdsByRouteIdByHandle.TryGetValue(
            handle,
            out ConcurrentDictionary<QuicConnectionIdKey, ulong>? connectionIdsByRoute)
            && connectionIdsByRoute.TryGetValue(routeId, out connectionId);
    }

    private bool TryLookupRetainedStatelessResetBinding(
        ReadOnlySpan<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionStatelessResetBinding? binding)
    {
        binding = null;

        if (datagram.IsEmpty
            || !QuicPacketParser.TryClassifyHeaderForm(datagram, out QuicHeaderForm headerForm))
        {
            return false;
        }

        if (headerForm == QuicHeaderForm.Long)
        {
            if (!QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket longHeader)
                || longHeader.DestinationConnectionId.IsEmpty
                || !QuicConnectionIdKey.TryCreate(longHeader.DestinationConnectionId, out QuicConnectionIdKey routeId))
            {
                return false;
            }

            return TryLookupRetainedStatelessResetBinding(routeId, pathIdentity, out binding);
        }

        if ((datagram[0] & QuicPacketHeaderBits.HeaderFormBitMask) != 0
            || (datagram[0] & QuicPacketHeaderBits.FixedBitMask) == 0)
        {
            return false;
        }

        ReadOnlySpan<byte> connectionIdRemainder = datagram[1..];
        int maximumCandidateLength = Math.Min(connectionIdRemainder.Length, QuicConnectionIdKey.MaximumLength);
        for (int candidateLength = maximumCandidateLength; candidateLength > 0; candidateLength--)
        {
            if (!retainedStatelessResetBindingsByRouteLength.ContainsKey((byte)candidateLength)
                || !QuicConnectionIdKey.TryCreate(connectionIdRemainder[..candidateLength], out QuicConnectionIdKey routeId))
            {
                continue;
            }

            if (TryLookupRetainedStatelessResetBinding(routeId, pathIdentity, out binding))
            {
                return true;
            }
        }

        return false;
    }

    private bool TryLookupRetainedStatelessResetBinding(
        QuicConnectionIdKey routeId,
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionStatelessResetBinding? binding)
    {
        binding = null;

        if (!retainedStatelessResetBindingsByRouteLength.TryGetValue(
                routeId.Length,
                out ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionStatelessResetBinding>? retainedRoutes)
            || !retainedRoutes.TryGetValue(routeId, out QuicConnectionStatelessResetBinding? candidateBinding)
            || !IsSameRemoteEndpoint(candidateBinding.PathIdentity, pathIdentity))
        {
            return false;
        }

        binding = candidateBinding;
        return true;
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

    private bool TryPostPacketReceived(
        QuicConnectionHandle handle,
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        ulong? routedLocallyIssuedConnectionId,
        QuicEcnCounts? ecnCounts = null,
        byte[]? ownedDatagramBuffer = null,
        QuicReceiveBufferOwnership ownedDatagramBufferOwnership = default)
    {
        return host.TryPostPacketReceived(handle, new QuicConnectionPacketReceivedContext(
            clock.Ticks,
            pathIdentity,
            datagram,
            routedLocallyIssuedConnectionId,
            ecnCounts),
            ownedDatagramBuffer,
            ownedDatagramBufferOwnership);
    }

    private bool TryDispatchStatelessReset(
        ReadOnlyMemory<byte> datagram,
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionIngressResult result)
    {
        if (!TryCreateStatelessResetMatchKey(pathIdentity.RemoteAddress, datagram.Span, out QuicConnectionStatelessResetMatchKey matchKey)
            || !statelessResetBindingsByMatchKey.TryGetValue(matchKey, out QuicConnectionStatelessResetBinding? binding))
        {
            result = default;
            return false;
        }

        if (!host.TryPostEvent(binding.Handle, new QuicConnectionAcceptedStatelessResetEvent(clock.Ticks, pathIdentity, binding.ConnectionId)))
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

    private static bool TryCreateStatelessResetMatchKey(
        string remoteAddress,
        ReadOnlySpan<byte> datagram,
        out QuicConnectionStatelessResetMatchKey matchKey)
    {
        if (!QuicStatelessReset.IsPotentialStatelessReset(datagram)
            || !QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram, out ReadOnlySpan<byte> trailingToken)
            || !QuicConnectionStatelessResetTokenKey.TryCreate(trailingToken, out QuicConnectionStatelessResetTokenKey tokenKey))
        {
            matchKey = default;
            return false;
        }

        matchKey = new QuicConnectionStatelessResetMatchKey(remoteAddress, tokenKey);
        return true;
    }

    private static bool IsKnownStatelessResetTrigger(
        ReadOnlySpan<byte> datagram,
        ReadOnlySpan<byte> token)
    {
        return QuicStatelessReset.IsPotentialStatelessReset(datagram)
            && QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, token);
    }

    private bool TryMoveStatelessResetBinding(
        ulong connectionId,
        QuicConnectionStatelessResetBinding binding,
        QuicConnectionPathIdentity pathIdentity)
    {
        if (string.Equals(binding.PathIdentity.RemoteAddress, pathIdentity.RemoteAddress, StringComparison.Ordinal))
        {
            if (!EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(binding.PathIdentity, pathIdentity))
            {
                statelessResetBindingsByConnectionId[connectionId] = binding with { PathIdentity = pathIdentity };
            }

            return true;
        }

        if (!QuicConnectionStatelessResetTokenKey.TryCreate(binding.Token, out QuicConnectionStatelessResetTokenKey tokenKey))
        {
            return false;
        }

        QuicConnectionStatelessResetMatchKey oldKey = new(binding.PathIdentity.RemoteAddress, tokenKey);
        QuicConnectionStatelessResetBinding updatedBinding = binding with { PathIdentity = pathIdentity };
        QuicConnectionStatelessResetMatchKey newKey = new(pathIdentity.RemoteAddress, tokenKey);

        if (!statelessResetBindingsByMatchKey.TryAdd(newKey, updatedBinding))
        {
            return false;
        }

        statelessResetBindingsByMatchKey.TryRemove(oldKey, out _);
        statelessResetBindingsByConnectionId[connectionId] = updatedBinding;
        return true;
    }

    private void TryRemoveStatelessResetBinding(ulong connectionId, bool preserveEmissionState = false)
    {
        if (!statelessResetBindingsByConnectionId.TryGetValue(connectionId, out QuicConnectionStatelessResetBinding? binding)
            || !QuicConnectionStatelessResetTokenKey.TryCreate(binding.Token, out QuicConnectionStatelessResetTokenKey tokenKey))
        {
            return;
        }

        statelessResetBindingsByMatchKey.TryRemove(
            new QuicConnectionStatelessResetMatchKey(binding.PathIdentity.RemoteAddress, tokenKey),
            out _);

        if (!preserveEmissionState)
        {
            statelessResetBindingsByConnectionId.TryRemove(connectionId, out _);
            TryRemoveRetainedStatelessResetBindings(connectionId);
        }
    }

    private void TryRemoveRetainedStatelessResetBindings(ulong connectionId)
    {
        foreach ((byte routeLength, ConcurrentDictionary<QuicConnectionIdKey, QuicConnectionStatelessResetBinding> retainedRoutes) in retainedStatelessResetBindingsByRouteLength)
        {
            foreach ((QuicConnectionIdKey routeId, QuicConnectionStatelessResetBinding binding) in retainedRoutes)
            {
                if (binding.ConnectionId == connectionId)
                {
                    retainedRoutes.TryRemove(routeId, out _);
                }
            }

            if (retainedRoutes.IsEmpty)
            {
                retainedStatelessResetBindingsByRouteLength.TryRemove(routeLength, out _);
            }
        }
    }

    private bool TryReserveStatelessResetEmission(string remoteAddress)
    {
        if (maximumStatelessResetEmissionsPerRemoteAddress == 0)
        {
            return false;
        }

        while (true)
        {
            if (!statelessResetEmissionCountsByRemoteAddress.TryGetValue(remoteAddress, out int currentCount))
            {
                if (statelessResetEmissionCountsByRemoteAddress.TryAdd(remoteAddress, 1))
                {
                    return true;
                }

                continue;
            }

            if (currentCount >= maximumStatelessResetEmissionsPerRemoteAddress)
            {
                return false;
            }

            if (statelessResetEmissionCountsByRemoteAddress.TryUpdate(remoteAddress, currentCount + 1, currentCount))
            {
                return true;
            }
        }
    }

    private static bool IsSameRemoteEndpoint(QuicConnectionPathIdentity left, QuicConnectionPathIdentity right)
    {
        return string.Equals(left.RemoteAddress, right.RemoteAddress, StringComparison.Ordinal)
            && left.RemotePort == right.RemotePort;
    }

    private static bool IsSameLocalEndpoint(QuicConnectionPathIdentity left, QuicConnectionPathIdentity right)
    {
        return string.Equals(left.LocalAddress, right.LocalAddress, StringComparison.Ordinal)
            && left.LocalPort == right.LocalPort;
    }
}
