using System.ComponentModel;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P5-0003">Permanent registrations in this registry MUST include the following fields.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P5-0004">The Code field MUST be a short mnemonic for the parameter.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P5-0005">The Description field MUST be a brief description of the error code semantics.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0001">This section lists the defined QUIC transport error codes that MAY be used in a CONNECTION_CLOSE frame with a type of 0x1c.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P5-0003")]
[Requirement("REQ-QUIC-RFC9000-S22P5-0004")]
[Requirement("REQ-QUIC-RFC9000-S22P5-0005")]
[Requirement("REQ-QUIC-RFC9000-S20P1-0001")]
public sealed class REQ_QUIC_RFC9000_S20P1_0001
{
    public static TheoryData<ulong, string> StandardTransportErrorCodes => new()
    {
        { 0x00UL, nameof(QuicTransportErrorCode.NoError) },
        { 0x01UL, nameof(QuicTransportErrorCode.InternalError) },
        { 0x02UL, nameof(QuicTransportErrorCode.ConnectionRefused) },
        { 0x03UL, nameof(QuicTransportErrorCode.FlowControlError) },
        { 0x04UL, nameof(QuicTransportErrorCode.StreamLimitError) },
        { 0x05UL, nameof(QuicTransportErrorCode.StreamStateError) },
        { 0x06UL, nameof(QuicTransportErrorCode.FinalSizeError) },
        { 0x07UL, nameof(QuicTransportErrorCode.FrameEncodingError) },
        { 0x08UL, nameof(QuicTransportErrorCode.TransportParameterError) },
        { 0x09UL, nameof(QuicTransportErrorCode.ConnectionIdLimitError) },
        { 0x0AUL, nameof(QuicTransportErrorCode.ProtocolViolation) },
        { 0x0BUL, nameof(QuicTransportErrorCode.InvalidToken) },
        { 0x0CUL, nameof(QuicTransportErrorCode.ApplicationError) },
        { 0x0DUL, nameof(QuicTransportErrorCode.CryptoBufferExceeded) },
        { 0x0EUL, nameof(QuicTransportErrorCode.KeyUpdateError) },
        { 0x0FUL, nameof(QuicTransportErrorCode.AeadLimitReached) },
        { 0x10UL, nameof(QuicTransportErrorCode.NoViablePath) },
    };

    [Theory]
    [MemberData(nameof(StandardTransportErrorCodes))]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TransportErrorCodeRegistry_ExposesTheRFC9000Values(
        ulong wireValue,
        string expectedName)
    {
        QuicTransportErrorCode code = (QuicTransportErrorCode)wireValue;

        Assert.Equal(wireValue, (ulong)code);
        Assert.Equal(expectedName, code.ToString());

        FieldInfo? field = typeof(QuicTransportErrorCode).GetField(expectedName);
        Assert.NotNull(field);
        DescriptionAttribute? description = field!.GetCustomAttribute<DescriptionAttribute>();
        Assert.NotNull(description);
        Assert.NotEmpty(description!.Description);
    }
}
