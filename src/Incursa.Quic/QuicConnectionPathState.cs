// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Owns the connection's path tables and the small amount of path bookkeeping that hangs off them.
/// </summary>
internal sealed class QuicConnectionPathState
{
    private readonly int maximumRecentlyValidatedPaths;

    internal QuicConnectionPathState(int maximumRecentlyValidatedPaths)
    {
        this.maximumRecentlyValidatedPaths = maximumRecentlyValidatedPaths;
    }

    internal QuicConnectionActivePathRecord? ActivePath { get; set; }

    internal Dictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> CandidatePaths { get; } = [];

    internal Dictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> RecentlyValidatedPaths { get; } = [];

    internal string? LastValidatedRemoteAddress { get; set; }

    internal QuicConnectionPathIdentity? PreferredAddressOldPathIdentity { get; set; }

    internal bool HasValidatedPath
    {
        get
        {
            if (ActivePath?.IsValidated ?? false)
            {
                return true;
            }

            if (RecentlyValidatedPaths.Count > 0)
            {
                return true;
            }

            foreach (QuicConnectionCandidatePathRecord candidate in CandidatePaths.Values)
            {
                if (candidate.Validation.IsValidated && !candidate.Validation.IsAbandoned)
                {
                    return true;
                }
            }

            return false;
        }
    }

    internal bool TryGetCandidatePath(
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionCandidatePathRecord candidatePath)
    {
        return CandidatePaths.TryGetValue(pathIdentity, out candidatePath);
    }

    internal bool TryGetRecentlyValidatedPath(
        QuicConnectionPathIdentity pathIdentity,
        out QuicConnectionValidatedPathRecord validatedPath)
    {
        return RecentlyValidatedPaths.TryGetValue(pathIdentity, out validatedPath);
    }

    internal void AppendRecentlyValidatedPath(
        QuicConnectionPathIdentity pathIdentity,
        long nowTicks,
        QuicConnectionPathRecoverySnapshot? savedRecoverySnapshot,
        QuicConnectionPathAmplificationState amplificationState,
        QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState)
    {
        if (maximumRecentlyValidatedPaths == 0)
        {
            return;
        }

        RecentlyValidatedPaths[pathIdentity] = new QuicConnectionValidatedPathRecord(
            pathIdentity,
            ValidatedAtTicks: nowTicks,
            SavedRecoverySnapshot: savedRecoverySnapshot)
        {
            LastActivityTicks = nowTicks,
            AmplificationState = amplificationState.MarkAddressValidated(),
            MaximumDatagramSizeState = maximumDatagramSizeState,
        };

        if (RecentlyValidatedPaths.Count <= maximumRecentlyValidatedPaths)
        {
            return;
        }

        QuicConnectionPathIdentity? candidateToRemove = null;
        long oldestActivityTicks = long.MaxValue;
        foreach (KeyValuePair<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> entry in RecentlyValidatedPaths)
        {
            if (EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(entry.Key, pathIdentity))
            {
                continue;
            }

            if (entry.Value.LastActivityTicks < oldestActivityTicks)
            {
                oldestActivityTicks = entry.Value.LastActivityTicks;
                candidateToRemove = entry.Key;
            }
        }

        if (candidateToRemove.HasValue)
        {
            RecentlyValidatedPaths.Remove(candidateToRemove.Value);
        }
    }
}
