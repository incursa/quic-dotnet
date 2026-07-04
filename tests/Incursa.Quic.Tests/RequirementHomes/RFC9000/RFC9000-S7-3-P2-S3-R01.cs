// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-3-P2-S3-R01")]
public sealed class RFC9000_S7_3_P2_S3_R01
{
    [Fact]
    [Requirement("RFC9000-S7-3-P2-S3-R01")]
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
