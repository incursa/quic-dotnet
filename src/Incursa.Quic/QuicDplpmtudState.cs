// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicDplpmtudProbeOutcome
{
    None = 0,
    Acknowledged = 1,
    Lost = 2,
}

internal readonly record struct QuicDplpmtudPathSnapshot(
    ulong BasePlpmtuBytes,
    ulong MaximumPacketSizeBytes,
    int OutstandingProbeCount,
    ulong? LastProbePacketNumber,
    ulong? LastProbeSizeBytes,
    QuicDplpmtudProbeOutcome LastProbeOutcome);

internal sealed class QuicDplpmtudState
{
    internal const ulong BasePlpmtuBytes =
        QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

    private readonly ulong basePlpmtuBytes;
    private readonly Dictionary<QuicConnectionPathIdentity, PathState> paths = new();

    internal QuicDplpmtudState(ulong basePlpmtuBytes = BasePlpmtuBytes)
    {
        if (basePlpmtuBytes != BasePlpmtuBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(basePlpmtuBytes));
        }

        this.basePlpmtuBytes = basePlpmtuBytes;
    }

    internal QuicDplpmtudPathSnapshot GetPathSnapshot(QuicConnectionPathIdentity pathIdentity)
    {
        return GetOrCreatePathState(pathIdentity).CreateSnapshot();
    }

    internal bool TryTrackProbe(
        QuicConnectionPathIdentity pathIdentity,
        ulong packetNumber,
        ulong probeSizeBytes)
    {
        // CONTEXT: DPLPMTUD tracks only probes that can raise the MTU ceiling
        // SEE: code:src/Incursa.Quic/QuicDplpmtudState.cs#TryTrackProbe
        // Probes that do not exceed the current candidate packet size are
        // ignored so the per-path outstanding map only contains packets that
        // might discover a larger ceiling. Duplicate packet numbers are also
        // ignored to keep the path state bounded.
        PathState path = GetOrCreatePathState(pathIdentity);
        if (probeSizeBytes <= path.MaximumPacketSizeBytes
            || path.OutstandingProbeSizes.ContainsKey(packetNumber))
        {
            return false;
        }

        path.OutstandingProbeSizes.Add(packetNumber, probeSizeBytes);
        return true;
    }

    internal bool TryTrackPaddingProbe(
        QuicConnectionPathIdentity pathIdentity,
        ulong packetNumber,
        ulong probeSizeBytes,
        ulong ackElicitingPayloadSizeBytes,
        out ulong paddingFrameBytes)
    {
        paddingFrameBytes = 0;
        if (ackElicitingPayloadSizeBytes == 0
            || probeSizeBytes <= ackElicitingPayloadSizeBytes)
        {
            return false;
        }

        if (!TryTrackProbe(pathIdentity, packetNumber, probeSizeBytes))
        {
            return false;
        }

        paddingFrameBytes = probeSizeBytes - ackElicitingPayloadSizeBytes;
        return true;
    }

    internal bool TryRegisterProbeAcknowledged(QuicConnectionPathIdentity pathIdentity, ulong packetNumber)
    {
        if (!paths.TryGetValue(pathIdentity, out PathState? path)
            || !path.OutstandingProbeSizes.Remove(packetNumber, out ulong probeSizeBytes))
        {
            return false;
        }

        if (probeSizeBytes > path.MaximumPacketSizeBytes)
        {
            path.MaximumPacketSizeBytes = probeSizeBytes;
        }

        path.LastProbePacketNumber = packetNumber;
        path.LastProbeSizeBytes = probeSizeBytes;
        path.LastProbeOutcome = QuicDplpmtudProbeOutcome.Acknowledged;
        return true;
    }

    internal bool TryRegisterProbeLost(QuicConnectionPathIdentity pathIdentity, ulong packetNumber)
    {
        if (!paths.TryGetValue(pathIdentity, out PathState? path)
            || !path.OutstandingProbeSizes.Remove(packetNumber, out ulong probeSizeBytes))
        {
            return false;
        }

        path.LastProbePacketNumber = packetNumber;
        path.LastProbeSizeBytes = probeSizeBytes;
        path.LastProbeOutcome = QuicDplpmtudProbeOutcome.Lost;
        return true;
    }

    private PathState GetOrCreatePathState(QuicConnectionPathIdentity pathIdentity)
    {
        if (!paths.TryGetValue(pathIdentity, out PathState? path))
        {
            path = new PathState(basePlpmtuBytes);
            paths.Add(pathIdentity, path);
        }

        return path;
    }

    private sealed class PathState
    {
        internal PathState(ulong basePlpmtuBytes)
        {
            PathBasePlpmtuBytes = basePlpmtuBytes;
            MaximumPacketSizeBytes = basePlpmtuBytes;
        }

        internal ulong PathBasePlpmtuBytes { get; }

        internal ulong MaximumPacketSizeBytes { get; set; }

        internal Dictionary<ulong, ulong> OutstandingProbeSizes { get; } = new();

        internal ulong? LastProbePacketNumber { get; set; }

        internal ulong? LastProbeSizeBytes { get; set; }

        internal QuicDplpmtudProbeOutcome LastProbeOutcome { get; set; }

        internal QuicDplpmtudPathSnapshot CreateSnapshot()
        {
            return new QuicDplpmtudPathSnapshot(
                PathBasePlpmtuBytes,
                MaximumPacketSizeBytes,
                OutstandingProbeSizes.Count,
                LastProbePacketNumber,
                LastProbeSizeBytes,
                LastProbeOutcome);
        }
    }
}
