// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Tests;

public sealed class Http3FieldSectionDecodeCacheTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Cache_ReusesSmallRequiredInsertCountZeroFieldSections()
    {
        Http3FieldSectionDecodeCache cache = new();
        byte[] encoded = Convert.FromHexString("0000D1D7508925A849E95BA97D7F");
        IReadOnlyList<QPackFieldLine> fields =
        [
            new QPackFieldLine(":method", "GET"),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":path", "/bytes/1kb"),
        ];

        Assert.False(cache.TryGet(encoded, out _));

        cache.Store(encoded, fields);

        Assert.True(cache.TryGet(encoded, out IReadOnlyList<QPackFieldLine>? cached));
        Assert.Same(fields, cached);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Cache_IgnoresFieldSectionsThatMayDependOnDynamicTableState()
    {
        Http3FieldSectionDecodeCache cache = new();
        byte[] encoded = Convert.FromHexString("0100D1");
        IReadOnlyList<QPackFieldLine> fields = [new QPackFieldLine(":method", "GET")];

        cache.Store(encoded, fields);

        Assert.False(cache.TryGet(encoded, out _));
    }
}
