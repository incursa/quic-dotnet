using System.ComponentModel;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P5-0005")]
public sealed class REQ_QUIC_RFC9000_S22P5_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_UsesBriefDescriptions()
    {
        foreach ((ulong wireValue, _, string expectedDescription) in QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes)
        {
            QuicTransportErrorCode code = (QuicTransportErrorCode)wireValue;

            Assert.Equal(wireValue, (ulong)code);

            FieldInfo? field = typeof(QuicTransportErrorCode).GetField(code.ToString());
            Assert.NotNull(field);

            DescriptionAttribute? description = field!.GetCustomAttribute<DescriptionAttribute>();
            Assert.NotNull(description);
            Assert.Equal(expectedDescription, description!.Description);
        }
    }
}
