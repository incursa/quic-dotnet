namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P3-0003">Permanent registrations in this registry MUST include the Parameter Name field.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P3-0004">The Parameter Name field MUST be a short mnemonic for the parameter.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P3-0003")]
[Requirement("REQ-QUIC-RFC9000-S22P3-0004")]
public sealed class QuicTransportParametersTests
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S10-0001">IANA MUST register codepoint 57 (0x39) for the quic_transport_parameters extension in the TLS ExtensionType Values registry.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S10-0002">The Recommended column for the quic_transport_parameters extension MUST be marked Yes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S10-0003">The TLS 1.3 column for the quic_transport_parameters extension MUST include CH (ClientHello) and EE (EncryptedExtensions).</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S10-0001")]
    [Requirement("REQ-QUIC-RFC9001-S10-0002")]
    [Requirement("REQ-QUIC-RFC9001-S10-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void QuicTransportParametersCodec_ExposesTheRegisteredTlsExtensionMetadata()
    {
        Assert.Equal((ushort)57, QuicTransportParametersCodec.QuicTransportParametersExtensionType);
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersRecommended);
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersClientHello);
        Assert.True(QuicTransportParametersCodec.QuicTransportParametersEncryptedExtensions);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S8-0001">The TLS handshake MUST carry values for QUIC transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0003">Each endpoint MUST advertise a `max_idle_timeout`, and the effective value at an endpoint is the minimum of the two advertised values, or the sole advertised value if only one endpoint advertises a non-zero value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0002">They MUST be encoded as a sequence of transport parameters, as shown in Figure 20:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0003">Each transport parameter MUST be encoded as an (identifier, length, value) tuple, as shown in Figure 21:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0004">The Transport Parameter ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0005">The Transport Parameter Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0006">The Transport Parameter Length field MUST contain the length of the Transport Parameter Value field in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0007">QUIC MUST encode transport parameters into a sequence of bytes, which is then included in the cryptographic handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0002">The maximum idle timeout is a value in milliseconds that MUST be encoded as an integer; see (Section 10.1).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0007">UDP datagrams with payloads larger than this limit MUST NOT be likely to be processed by the receiver.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0008">The initial maximum data parameter is an integer value that contains the initial value for the maximum amount of data that MAY be sent on the connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0010">The initial maximum bidirectional streams parameter is an integer value that MUST contain the initial maximum number of bidirectional streams the endpoint that receives this transport parameter is permitted to initiate.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0013">The initial maximum unidirectional streams parameter is an integer value that MUST contain the initial maximum number of unidirectional streams the endpoint that receives this transport parameter is permitted to initiate.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0015">This value SHOULD include the receiver&apos;s expected delays in alarms firing.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0016">The disable active migration transport parameter is included if the endpoint MUST NOT support active connection migration (Section 9) on the address being used during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0035">The value of the active_connection_id_limit parameter MUST be at least 2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0018">Servers MAY issue a stateless_reset_token transport parameter during the handshake that applies to the connection ID that it selected during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2P3-0004">A server in a deployment that does not implement a solution to maintain connection continuity when the client address changes SHOULD indicate that migration is not supported by using the disable_active_migration transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0011">Endpoints MUST advertise the number of active connection IDs they are willing to maintain using the active_connection_id_limit transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0002">Each endpoint MUST include the value of the Source Connection ID field from the first Initial packet it sent in the initial_source_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0005">A receiver MUST set initial limits for all streams through transport parameters during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0003">Initial limits MUST be set in the transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0005">Separate limits MUST apply to unidirectional and bidirectional streams.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18-0006")]
    [Requirement("REQ-QUIC-RFC9000-S18-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0035")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0018")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_WritesExactTupleSequence()
    {
        byte[] statelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0xA0 + value)).ToArray();
        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 25,
            StatelessResetToken = statelessResetToken,
            MaxUdpPayloadSize = 1200,
            InitialMaxData = 1000,
            InitialMaxStreamDataBidiLocal = 2000,
            InitialMaxStreamDataBidiRemote = 3000,
            InitialMaxStreamDataUni = 4000,
            InitialMaxStreamsBidi = 4,
            InitialMaxStreamsUni = 3,
            MaxAckDelay = 33,
            DisableActiveMigration = true,
            ActiveConnectionIdLimit = 8,
            InitialSourceConnectionId = [0x11, 0x22],
        };

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x02, statelessResetToken),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x03, QuicVarintTestData.EncodeMinimal(1200)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x04, QuicVarintTestData.EncodeMinimal(1000)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x05, QuicVarintTestData.EncodeMinimal(2000)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x06, QuicVarintTestData.EncodeMinimal(3000)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x07, QuicVarintTestData.EncodeMinimal(4000)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x08, QuicVarintTestData.EncodeMinimal(4)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x09, QuicVarintTestData.EncodeMinimal(3)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0B, QuicVarintTestData.EncodeMinimal(33)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0C, []),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0E, QuicVarintTestData.EncodeMinimal(8)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, [0x11, 0x22]));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S8-0001">The TLS handshake MUST carry values for QUIC transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0003">Each endpoint MUST advertise a `max_idle_timeout`, and the effective value at an endpoint is the minimum of the two advertised values, or the sole advertised value if only one endpoint advertises a non-zero value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0011">Endpoints MUST advertise the number of active connection IDs they are willing to maintain using the active_connection_id_limit transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0002">Each endpoint MUST include the value of the Source Connection ID field from the first Initial packet it sent in the initial_source_connection_id transport parameter.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsActiveConnectionIdLimitWhenSendingAsClient()
    {
        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 25,
            ActiveConnectionIdLimit = 8,
            InitialSourceConnectionId = [0x11, 0x22],
        };

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0E, QuicVarintTestData.EncodeMinimal(8)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0F, [0x11, 0x22]));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.Equal(parameters.MaxIdleTimeout, parsed.MaxIdleTimeout);
        Assert.Equal(parameters.ActiveConnectionIdLimit, parsed.ActiveConnectionIdLimit);
        Assert.True(parameters.InitialSourceConnectionId!.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId!));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S8-0001">The TLS handshake MUST carry values for QUIC transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P1-0003">Each endpoint MUST advertise a `max_idle_timeout`, and the effective value at an endpoint is the minimum of the two advertised values, or the sole advertised value if only one endpoint advertises a non-zero value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0001">The extension_data field of the quic_transport_parameters extension defined in [QUIC-TLS] MUST contain the QUIC transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0002">They MUST be encoded as a sequence of transport parameters, as shown in Figure 20:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0003">Each transport parameter MUST be encoded as an (identifier, length, value) tuple, as shown in Figure 21:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0004">The Transport Parameter ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0005">The Transport Parameter Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0006">The Transport Parameter Length field MUST contain the length of the Transport Parameter Value field in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0007">QUIC MUST encode transport parameters into a sequence of bytes, which is then included in the cryptographic handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0001">Transport parameters with an identifier of the form 31 * N + 27 for integer values of N MUST be reserved to exercise the requirement that unknown transport parameters be ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0002">These transport parameters have no semantics and MAY carry arbitrary values.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0001">This transport parameter MUST only be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0001">The choice each endpoint makes about connection IDs during the handshake MUST be authenticated by including all values in transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0003">A server MUST include the Destination Connection ID field from the first Initial packet it received from the client in the original_destination_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0004">If it sends a Retry packet, a server MUST also include the Source Connection ID field from the Retry packet in the retry_source_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0004">This transport parameter MAY be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0005">This transport parameter MUST NOT be sent by a client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0019">The server&apos;s preferred address MUST be used to effect a change in server address at the end of the handshake, as described in Section 9.6.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0020">Servers MAY choose to only send a preferred address of one address family by sending an all-zero address and port (0.0.0.0:0 or [::]:0) for the other family.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0021">IP addresses MUST be encoded in network byte order.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0022">The preferred_address transport parameter MUST contain an address and port for both IPv4 and IPv6.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0023">Finally, a 16-byte Stateless Reset Token field MUST include the stateless reset token associated with the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0025">A server that chooses a zero-length connection ID MUST NOT provide a preferred address.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0026">Similarly, a server MUST NOT include a zero-length connection ID in this transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0028">The IPv4 Address field MUST be 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0029">The IPv4 Port field MUST be 16 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0030">The IPv6 Address field MUST be 128 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0031">The IPv6 Port field MUST be 16 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0032">The Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0033">The Stateless Reset Token field MUST be 128 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0035">The value of the active_connection_id_limit parameter MUST be at least 2.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2P3-0002">If servers can use a dedicated server IP address or port other than the one that the client initially connects to, they MAY use the preferred_address transport parameter to request that clients move connections to that dedicated address.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P2P3-0004">A server in a deployment that does not implement a solution to maintain connection continuity when the client address changes SHOULD indicate that migration is not supported by using the disable_active_migration transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0011">Endpoints MUST advertise the number of active connection IDs they are willing to maintain using the active_connection_id_limit transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0018">Servers MAY issue a stateless_reset_token transport parameter during the handshake that applies to the connection ID that it selected during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0005">A receiver MUST set initial limits for all streams through transport parameters during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0003">Initial limits MUST be set in the transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0005">Separate limits MUST apply to unidirectional and bidirectional streams.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6P1-0001">Servers MAY communicate a preferred address of each address family (IPv4 and IPv6) to allow clients to pick the one most suited to their network attachment.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6P1-0007">Servers MAY communicate a preferred address of each address family to allow clients to pick the one most suited to their network attachment.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18-0006")]
    [Requirement("REQ-QUIC-RFC9000-S18-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0019")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0020")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0021")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0022")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0023")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0025")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0026")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0028")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0029")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0030")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0031")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0032")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0033")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0035")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0018")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseTransportParameters_RoundTripsKnownFieldsAndPreferredAddress()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = [0x01, 0x02, 0x03],
            MaxIdleTimeout = 25,
            StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x20 + value)).ToArray(),
            MaxUdpPayloadSize = 1350,
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 8192,
            InitialMaxStreamDataBidiRemote = 12288,
            InitialMaxStreamDataUni = 16384,
            InitialMaxStreamsBidi = 6,
            InitialMaxStreamsUni = 7,
            MaxAckDelay = 33,
            DisableActiveMigration = true,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                IPv6Port = 8443,
                ConnectionId = [0xAA, 0xBB],
                StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x10 + value)).ToArray(),
            },
            ActiveConnectionIdLimit = 8,
            InitialSourceConnectionId = [0x11, 0x22],
            RetrySourceConnectionId = [0x33, 0x44, 0x55],
        };

        Span<byte> destination = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.True(parameters.OriginalDestinationConnectionId!.AsSpan().SequenceEqual(parsed.OriginalDestinationConnectionId!));
        Assert.Equal(parameters.MaxIdleTimeout, parsed.MaxIdleTimeout);
        Assert.True(parameters.StatelessResetToken!.AsSpan().SequenceEqual(parsed.StatelessResetToken!));
        Assert.Equal(parameters.MaxUdpPayloadSize, parsed.MaxUdpPayloadSize);
        Assert.Equal(parameters.InitialMaxData, parsed.InitialMaxData);
        Assert.Equal(parameters.InitialMaxStreamDataBidiLocal, parsed.InitialMaxStreamDataBidiLocal);
        Assert.Equal(parameters.InitialMaxStreamDataBidiRemote, parsed.InitialMaxStreamDataBidiRemote);
        Assert.Equal(parameters.InitialMaxStreamDataUni, parsed.InitialMaxStreamDataUni);
        Assert.Equal(parameters.InitialMaxStreamsBidi, parsed.InitialMaxStreamsBidi);
        Assert.Equal(parameters.InitialMaxStreamsUni, parsed.InitialMaxStreamsUni);
        Assert.Equal(parameters.MaxAckDelay, parsed.MaxAckDelay);
        Assert.True(parsed.DisableActiveMigration);
        Assert.NotNull(parsed.PreferredAddress);
        Assert.True(parameters.PreferredAddress!.IPv4Address.AsSpan().SequenceEqual(parsed.PreferredAddress!.IPv4Address));
        Assert.Equal(parameters.PreferredAddress.IPv4Port, parsed.PreferredAddress.IPv4Port);
        Assert.True(parameters.PreferredAddress.IPv6Address.AsSpan().SequenceEqual(parsed.PreferredAddress.IPv6Address));
        Assert.Equal(parameters.PreferredAddress.IPv6Port, parsed.PreferredAddress.IPv6Port);
        Assert.True(parameters.PreferredAddress.ConnectionId.AsSpan().SequenceEqual(parsed.PreferredAddress.ConnectionId));
        Assert.True(parameters.PreferredAddress.StatelessResetToken.AsSpan().SequenceEqual(parsed.PreferredAddress.StatelessResetToken));
        Assert.Equal(parameters.ActiveConnectionIdLimit, parsed.ActiveConnectionIdLimit);
        Assert.True(parameters.InitialSourceConnectionId!.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId!));
        Assert.True(parameters.RetrySourceConnectionId!.AsSpan().SequenceEqual(parsed.RetrySourceConnectionId!));
    }

    [Theory]
    [InlineData(0x08UL)]
    [InlineData(0x09UL)]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0006">If an oversized max_streams value is received in a transport parameter, the connection MUST be closed immediately with TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseAndFormatTransportParameters_RejectsInitialMaxStreamsAboveTheEncodingLimit(ulong parameterId)
    {
        ulong overLimit = (1UL << 60) + 1;
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(parameterId, QuicVarintTestData.EncodeMinimal(overLimit));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));

        QuicTransportParameters parameters = parameterId == 0x08UL
            ? new QuicTransportParameters { InitialMaxStreamsBidi = overLimit }
            : new QuicTransportParameters { InitialMaxStreamsUni = overLimit };

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            stackalloc byte[16],
            out _));
    }

    public static IEnumerable<object[]> MatchingConnectionIdBindingCases()
    {
        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            true,
            new byte[] { 0x30 },
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
                RetrySourceConnectionId = new byte[] { 0x30 },
            },
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Server,
            Array.Empty<byte>(),
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
        };
    }

    public static IEnumerable<object[]> MissingConnectionIdBindingCases()
    {
        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
            QuicConnectionIdBindingValidationError.MissingOriginalDestinationConnectionId,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
            },
            QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            true,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
            QuicConnectionIdBindingValidationError.MissingRetrySourceConnectionId,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Server,
            Array.Empty<byte>(),
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters(),
            QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId,
        };
    }

    public static IEnumerable<object[]> MismatchedConnectionIdBindingCases()
    {
        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x99 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
            },
            QuicConnectionIdBindingValidationError.OriginalDestinationConnectionIdMismatch,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x99 },
            },
            QuicConnectionIdBindingValidationError.InitialSourceConnectionIdMismatch,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            true,
            new byte[] { 0x30 },
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
                RetrySourceConnectionId = new byte[] { 0x99 },
            },
            QuicConnectionIdBindingValidationError.RetrySourceConnectionIdMismatch,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Client,
            new byte[] { 0x10, 0x11 },
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                OriginalDestinationConnectionId = new byte[] { 0x10, 0x11 },
                InitialSourceConnectionId = new byte[] { 0x20, 0x21 },
                RetrySourceConnectionId = new byte[] { 0x30 },
            },
            QuicConnectionIdBindingValidationError.UnexpectedRetrySourceConnectionId,
        };

        yield return new object[]
        {
            QuicTransportParameterRole.Server,
            Array.Empty<byte>(),
            new byte[] { 0x20, 0x21 },
            false,
            Array.Empty<byte>(),
            new QuicTransportParameters
            {
                InitialSourceConnectionId = new byte[] { 0x99 },
            },
            QuicConnectionIdBindingValidationError.InitialSourceConnectionIdMismatch,
        };
    }

}
