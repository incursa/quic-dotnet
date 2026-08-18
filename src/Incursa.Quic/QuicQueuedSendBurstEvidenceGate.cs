// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal static class QuicQueuedSendBurstEvidenceGate
{
    internal static bool HasLegalBudgetGreaterThanOne(
        in QuicQueuedSendBurstEvidence evidence)
        => evidence.LegalMaximumDatagrams > 1;
}
