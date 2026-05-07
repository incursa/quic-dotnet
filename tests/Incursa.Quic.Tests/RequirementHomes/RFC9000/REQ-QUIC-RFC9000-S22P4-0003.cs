using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P4-0003")]
public sealed class REQ_QUIC_RFC9000_S22P4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FrameRegistrations_IncludeTheFrameTypeNameField()
    {
        foreach ((string fieldName, ulong wireValue, string frameTypeName, _) in QuicFrameRegistryProofSupport.DefinedFrameRegistrations)
        {
            FieldInfo? field = typeof(QuicFrameCodec).GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Static);

            Assert.NotNull(field);
            Assert.Equal(fieldName, field!.Name);
            Assert.Equal(wireValue, (ulong)field.GetRawConstantValue()!);
            Assert.NotEmpty(frameTypeName);
        }
    }
}
