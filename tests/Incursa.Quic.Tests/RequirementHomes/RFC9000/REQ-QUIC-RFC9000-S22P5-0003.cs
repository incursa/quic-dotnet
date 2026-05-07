using System.ComponentModel;
using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P5-0003")]
public sealed class REQ_QUIC_RFC9000_S22P5_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TransportErrorCodeRegistry_IncludesCodeAndDescriptionFields()
    {
        foreach ((ulong wireValue, string expectedName, _) in QuicTransportErrorCodeRegistryProofSupport.DefinedTransportErrorCodes)
        {
            QuicTransportErrorCode code = (QuicTransportErrorCode)wireValue;

            Assert.Equal(wireValue, (ulong)code);

            FieldInfo? field = typeof(QuicTransportErrorCode).GetField(expectedName);
            Assert.NotNull(field);

            DescriptionAttribute? description = field!.GetCustomAttribute<DescriptionAttribute>();
            Assert.NotNull(description);
            Assert.NotEmpty(description!.Description);
        }
    }
}
