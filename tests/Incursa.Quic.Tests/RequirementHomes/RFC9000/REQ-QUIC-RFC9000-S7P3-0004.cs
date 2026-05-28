// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P3-0004")]
public sealed class REQ_QUIC_RFC9000_S7P3_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsRetrySourceConnectionIdFromServer()
    {
        QuicTransportParameters parameters = new()
        {
            RetrySourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.RetrySourceConnectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);

        Assert.Equal(parameters.RetrySourceConnectionId, parsed.RetrySourceConnectionId);
    }
}
