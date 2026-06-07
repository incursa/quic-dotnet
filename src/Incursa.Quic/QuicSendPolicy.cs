// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicSendPolicyBlockedReason
{
    None,
    NoQueuedApplicationData,
    NoActivePath,
    OrdinaryPacketsUnavailable,
    OneRttProtectionUnavailable,
    ApplicationDataRetransmissionPending,
    InvalidPayloadBudget,
    CongestionLimited,
    AntiAmplificationLimited,
    InvalidQueuedApplicationSend,
}

internal readonly record struct QuicSendPolicySnapshot(
    bool HasActivePath,
    bool CanSendOrdinaryPackets,
    ulong MaximumDatagramSizeBytes,
    int MaximumApplicationPayloadBytes,
    ulong CongestionWindowBytes,
    ulong BytesInFlightBytes,
    int PendingRetransmissionCount,
    bool HasApplicationDataRetransmission,
    ulong AntiAmplificationAvailableBytes,
    bool IsAddressValidated,
    bool HandshakeConfirmed,
    bool HasOneRttProtection,
    int QueuedApplicationSendCount);

internal readonly record struct QuicQueuedApplicationSendBudget(
    bool CanSendQueuedApplicationData,
    int MaxDatagrams,
    int MaxPayloadBytes,
    QuicSendPolicyBlockedReason BlockedReason,
    bool ShouldPrioritizeRetransmission)
{
    internal static QuicQueuedApplicationSendBudget Allowed(int maxDatagrams, int maxPayloadBytes)
        => maxDatagrams <= 0 || maxPayloadBytes <= 0
            ? Blocked(QuicSendPolicyBlockedReason.InvalidPayloadBudget)
            : new(
                CanSendQueuedApplicationData: true,
                maxDatagrams,
                maxPayloadBytes,
                QuicSendPolicyBlockedReason.None,
                ShouldPrioritizeRetransmission: false);

    internal static QuicQueuedApplicationSendBudget AllowSingleDatagram(int maxPayloadBytes)
        => Allowed(maxDatagrams: 1, maxPayloadBytes);

    internal static QuicQueuedApplicationSendBudget Blocked(
        QuicSendPolicyBlockedReason reason,
        bool shouldPrioritizeRetransmission = false)
        => new(
            CanSendQueuedApplicationData: false,
            MaxDatagrams: 0,
            MaxPayloadBytes: 0,
            reason,
            shouldPrioritizeRetransmission);
}

internal static class QuicSendPolicy
{
    // CONTEXT: transitional measured raw-QUIC queued stream send burst cap.
    // Follow-up: replace this datagram-count cap with byte/packet pacing once
    // the send-policy pilot has enough ProtocolLab evidence across multiplexed
    // and duplex workloads.
    internal const int MeasuredQueuedApplicationSendBurstDatagrams = 4;

    internal static QuicQueuedApplicationSendBudget ComputeQueuedApplicationSendBudget(
        QuicSendPolicySnapshot snapshot)
    {
        if (snapshot.QueuedApplicationSendCount <= 0)
        {
            return QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.NoQueuedApplicationData);
        }

        if (!snapshot.HasActivePath)
        {
            return QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.NoActivePath);
        }

        if (!snapshot.CanSendOrdinaryPackets)
        {
            return QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.OrdinaryPacketsUnavailable);
        }

        if (!snapshot.HasOneRttProtection)
        {
            return QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.OneRttProtectionUnavailable);
        }

        if (snapshot.HasApplicationDataRetransmission)
        {
            return QuicQueuedApplicationSendBudget.Blocked(
                QuicSendPolicyBlockedReason.ApplicationDataRetransmissionPending,
                shouldPrioritizeRetransmission: true);
        }

        if (snapshot.MaximumDatagramSizeBytes == 0 || snapshot.MaximumApplicationPayloadBytes <= 0)
        {
            return QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.InvalidPayloadBudget);
        }

        ulong congestionAvailableBytes = snapshot.CongestionWindowBytes > snapshot.BytesInFlightBytes
            ? snapshot.CongestionWindowBytes - snapshot.BytesInFlightBytes
            : 0;
        if (congestionAvailableBytes == 0)
        {
            return QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.CongestionLimited);
        }

        ulong sendAvailableBytes = congestionAvailableBytes;
        if (!snapshot.IsAddressValidated)
        {
            if (snapshot.AntiAmplificationAvailableBytes == 0)
            {
                return QuicQueuedApplicationSendBudget.Blocked(QuicSendPolicyBlockedReason.AntiAmplificationLimited);
            }

            sendAvailableBytes = Math.Min(sendAvailableBytes, snapshot.AntiAmplificationAvailableBytes);
        }

        ulong datagramsBySendBudget = CountDatagramsAllowedByAvailableBytes(
            sendAvailableBytes,
            snapshot.MaximumDatagramSizeBytes);
        if (datagramsBySendBudget == 0)
        {
            return QuicQueuedApplicationSendBudget.Blocked(
                snapshot.IsAddressValidated
                    ? QuicSendPolicyBlockedReason.CongestionLimited
                    : QuicSendPolicyBlockedReason.AntiAmplificationLimited);
        }

        ulong maxDatagrams = Math.Min(
            (ulong)MeasuredQueuedApplicationSendBurstDatagrams,
            datagramsBySendBudget);
        int maxPayloadBytes = (int)Math.Min(
            (ulong)snapshot.MaximumApplicationPayloadBytes,
            Math.Min(sendAvailableBytes, (ulong)int.MaxValue));

        return QuicQueuedApplicationSendBudget.Allowed((int)maxDatagrams, maxPayloadBytes);
    }

    private static ulong CountDatagramsAllowedByAvailableBytes(
        ulong availableBytes,
        ulong maximumDatagramSizeBytes)
    {
        if (availableBytes == 0)
        {
            return 0;
        }

        ulong fullDatagrams = availableBytes / maximumDatagramSizeBytes;
        ulong remainderBytes = availableBytes % maximumDatagramSizeBytes;
        return remainderBytes > 0
            ? fullDatagrams + 1
            : fullDatagrams;
    }
}
