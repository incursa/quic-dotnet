namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S22P4-0004")]
public sealed class REQ_QUIC_RFC9000_S22P4_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FrameRegistrations_UseShortMnemonicFrameTypeNames()
    {
        foreach ((_, _, string frameTypeName, _) in QuicFrameRegistryProofSupport.DefinedFrameRegistrations)
        {
            Assert.InRange(frameTypeName.Length, 1, 20);

            foreach (char character in frameTypeName)
            {
                Assert.True(char.IsUpper(character) || char.IsDigit(character) || character == '_');
            }
        }
    }
}
