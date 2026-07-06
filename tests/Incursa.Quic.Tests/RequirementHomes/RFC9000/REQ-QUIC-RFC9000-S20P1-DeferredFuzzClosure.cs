// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.ComponentModel;
using System.Reflection;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S20P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TransportErrorCodeRegistryFuzz_ExposesOnlyDefinedRFC9000TransportCodes()
    {
        HashSet<ulong> definedWireValues = QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes
            .Select(candidate => candidate.WireValue)
            .ToHashSet();

        ulong[] samples =
        [
            0x00UL,
            0x01UL,
            0x03UL,
            0x08UL,
            0x0DUL,
            0x10UL,
            0x11UL,
            0x12UL,
            0x7FUL,
            0xFFUL,
            0x0100UL,
            0x01FFUL,
            0x0200UL,
            0x3FFF_FFFF_FFFF_FFFFUL,
        ];

        foreach (ulong wireValue in samples)
        {
            bool isDefined = Enum.IsDefined(typeof(QuicTransportErrorCode), wireValue);
            Assert.Equal(definedWireValues.Contains(wireValue), isDefined);

            if (!isDefined)
            {
                Assert.Null(Enum.GetName(typeof(QuicTransportErrorCode), wireValue));
                continue;
            }

            QuicTransportErrorCode code = (QuicTransportErrorCode)wireValue;
            string expectedName = QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes
                .Single(candidate => candidate.WireValue == wireValue)
                .ExpectedName;

            Assert.Equal(expectedName, code.ToString());
            AssertTransportErrorCodeFieldIsDocumented(expectedName);
        }
    }

    private static void AssertTransportErrorCodeFieldIsDocumented(string expectedName)
    {
        FieldInfo? field = typeof(QuicTransportErrorCode).GetField(expectedName);
        Assert.NotNull(field);

        DescriptionAttribute? description = field!.GetCustomAttribute<DescriptionAttribute>();
        Assert.NotNull(description);
        Assert.NotEmpty(description!.Description);
    }
}
