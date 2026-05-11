namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P21-0011")]
public sealed class REQ_QUIC_RFC9000_S19P21_0011
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P21-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FrameRegistry_UsesThePermanentFrameTypeTableToManageAssignments()
    {
        Assert.Equal(23, QuicFrameRegistryProofSupport.PermanentFrameTypes.Length);

        ulong previousFrameType = 0;
        bool seenFirst = false;

        foreach ((ulong frameType, string frameTypeName, string fieldSemantics) in QuicFrameRegistryProofSupport.PermanentFrameTypes)
        {
            Assert.NotEmpty(frameTypeName);
            Assert.NotEmpty(fieldSemantics);

            if (seenFirst)
            {
                Assert.True(frameType > previousFrameType);
            }
            else
            {
                seenFirst = true;
            }

            previousFrameType = frameType;
        }

        Assert.Equal(0x00UL, QuicFrameRegistryProofSupport.PermanentFrameTypes[0].FrameType);
        Assert.Equal("PADDING", QuicFrameRegistryProofSupport.PermanentFrameTypes[0].FrameTypeName);
        Assert.Equal(0x1EUL, QuicFrameRegistryProofSupport.PermanentFrameTypes[^1].FrameType);
        Assert.Equal("HANDSHAKE_DONE", QuicFrameRegistryProofSupport.PermanentFrameTypes[^1].FrameTypeName);
    }
}
