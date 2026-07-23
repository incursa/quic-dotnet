// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Immutable, connection-construction provenance for a forced application-send turn campaign.
/// </summary>
/// <remarks>
/// This write-only evidence record is not an observation and is never consumed by a planner.
/// </remarks>
internal readonly record struct QuicApplicationSendTurnPolicyProvenance(
    string SchemaVersion,
    string AxisId,
    string RuleVersion,
    QuicApplicationSendTurnPolicyMode AppliedPolicy)
{
    internal const string CurrentSchemaVersion = "adaptive-runtime-application-send-turn-provenance-v1";
    internal const string CurrentAxisId = "application_send_turn_planning";
    internal const string CurrentRuleVersion = "application-send-turn-force-v1";

    internal static QuicApplicationSendTurnPolicyProvenance Create(
        QuicApplicationSendTurnPolicyMode appliedPolicy)
        => new(
            CurrentSchemaVersion,
            CurrentAxisId,
            CurrentRuleVersion,
            appliedPolicy);
}

internal interface IQuicApplicationSendTurnPolicyProvenanceSink
{
    bool TryPublish(in QuicApplicationSendTurnPolicyProvenance provenance);
}
