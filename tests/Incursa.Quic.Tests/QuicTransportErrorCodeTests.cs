using System.ComponentModel;
using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P5-0003">Permanent registrations in this registry MUST include the following fields.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P5-0004">The Code field MUST be a short mnemonic for the parameter.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P5-0005">The Description field MUST be a brief description of the error code semantics.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P5-0003")]
[Requirement("REQ-QUIC-RFC9000-S22P5-0004")]
[Requirement("REQ-QUIC-RFC9000-S22P5-0005")]
public sealed class QuicTransportErrorCodeTests
{
    public static TheoryData<QuicTransportErrorCode, ulong, string> StandardTransportErrorCodes => new()
    {
        { QuicTransportErrorCode.NoError, 0x00, nameof(QuicTransportErrorCode.NoError) },
        { QuicTransportErrorCode.InternalError, 0x01, nameof(QuicTransportErrorCode.InternalError) },
        { QuicTransportErrorCode.ConnectionRefused, 0x02, nameof(QuicTransportErrorCode.ConnectionRefused) },
        { QuicTransportErrorCode.FlowControlError, 0x03, nameof(QuicTransportErrorCode.FlowControlError) },
        { QuicTransportErrorCode.StreamLimitError, 0x04, nameof(QuicTransportErrorCode.StreamLimitError) },
        { QuicTransportErrorCode.StreamStateError, 0x05, nameof(QuicTransportErrorCode.StreamStateError) },
        { QuicTransportErrorCode.FinalSizeError, 0x06, nameof(QuicTransportErrorCode.FinalSizeError) },
        { QuicTransportErrorCode.FrameEncodingError, 0x07, nameof(QuicTransportErrorCode.FrameEncodingError) },
        { QuicTransportErrorCode.TransportParameterError, 0x08, nameof(QuicTransportErrorCode.TransportParameterError) },
        { QuicTransportErrorCode.ConnectionIdLimitError, 0x09, nameof(QuicTransportErrorCode.ConnectionIdLimitError) },
        { QuicTransportErrorCode.ProtocolViolation, 0x0A, nameof(QuicTransportErrorCode.ProtocolViolation) },
        { QuicTransportErrorCode.InvalidToken, 0x0B, nameof(QuicTransportErrorCode.InvalidToken) },
        { QuicTransportErrorCode.ApplicationError, 0x0C, nameof(QuicTransportErrorCode.ApplicationError) },
        { QuicTransportErrorCode.CryptoBufferExceeded, 0x0D, nameof(QuicTransportErrorCode.CryptoBufferExceeded) },
        { QuicTransportErrorCode.KeyUpdateError, 0x0E, nameof(QuicTransportErrorCode.KeyUpdateError) },
        { QuicTransportErrorCode.AeadLimitReached, 0x0F, nameof(QuicTransportErrorCode.AeadLimitReached) },
        { QuicTransportErrorCode.NoViablePath, 0x10, nameof(QuicTransportErrorCode.NoViablePath) },
    };

    [Theory]
    [MemberData(nameof(StandardTransportErrorCodes))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0001">This section lists the defined QUIC transport error codes that MAY be used in a CONNECTION_CLOSE frame with a type of 0x1c.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0002">An endpoint MUST use this with CONNECTION_CLOSE to signal that the connection is being closed abruptly in the absence of any error.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0003">The endpoint encountered an internal error and MUST NOT continue with the connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0004">An endpoint has received more data in CRYPTO frames than it MAY buffer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0005">An endpoint is unlikely to receive a CONNECTION_CLOSE frame carrying this code except when the path MUST NOT support a large enough MTU.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0006">A range of 256 values is reserved for carrying error codes specific to the cryptographic handshake that MUST be used.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0007">Codes for errors occurring when TLS MUST be used for the cryptographic handshake are described in Section 4.8 of [QUIC-TLS].</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S20P1-0008">Absent either of these conditions, error codes MUST be used to identify a general function of the stack, like flow control or transport parameter handling.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S20P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S20P1-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TransportErrorCodeRegistry_ExposesTheRFC9000Values(
        QuicTransportErrorCode code,
        ulong expectedWireValue,
        string expectedName)
    {
        Assert.Equal(expectedWireValue, (ulong)code);
        Assert.Equal(expectedName, code.ToString());

        FieldInfo? field = typeof(QuicTransportErrorCode).GetField(expectedName);
        Assert.NotNull(field);
        DescriptionAttribute? description = field!.GetCustomAttribute<DescriptionAttribute>();
        Assert.NotNull(description);
        Assert.NotEmpty(description!.Description);
    }
}
