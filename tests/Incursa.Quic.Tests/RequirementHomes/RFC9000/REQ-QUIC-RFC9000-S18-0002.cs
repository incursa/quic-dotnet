namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18-0002")]
public sealed class REQ_QUIC_RFC9000_S18_0002
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S8-0001">The TLS handshake MUST carry values for QUIC transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0002">They MUST be encoded as a sequence of transport parameters, as shown in Figure 20:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0003">Each transport parameter MUST be encoded as an (identifier, length, value) tuple, as shown in Figure 21:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0004">The Transport Parameter ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0005">The Transport Parameter Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0006">The Transport Parameter Length field MUST contain the length of the Transport Parameter Value field in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0007">QUIC MUST encode transport parameters into a sequence of bytes, which is then included in the cryptographic handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0001">Transport parameters with an identifier of the form 31 * N + 27 for integer values of N MUST be reserved to exercise the requirement that unknown transport parameters be ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0002">These transport parameters have no semantics and MAY carry arbitrary values.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0001">This transport parameter MUST only be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0002">The maximum idle timeout is a value in milliseconds that MUST be encoded as an integer; see (Section 10.1).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0004">This transport parameter MAY be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0005">This transport parameter MUST NOT be sent by a client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0007">UDP datagrams with payloads larger than this limit MUST NOT be likely to be processed by the receiver.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0008">The initial maximum data parameter is an integer value that contains the initial value for the maximum amount of data that MAY be sent on the connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0010">The initial maximum bidirectional streams parameter is an integer value that MUST contain the initial maximum number of bidirectional streams the endpoint that receives this transport parameter is permitted to initiate.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0013">The initial maximum unidirectional streams parameter is an integer value that MUST contain the initial maximum number of unidirectional streams the endpoint that receives this transport parameter is permitted to initiate.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0015">This value SHOULD include the receiver&apos;s expected delays in alarms firing.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0016">The disable active migration transport parameter is included if the endpoint MUST NOT support active connection migration (Section 9) on the address being used during the handshake.</workbench-requirement>
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0001">The choice each endpoint makes about connection IDs during the handshake MUST be authenticated by including all values in transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0002">Each endpoint MUST include the value of the Source Connection ID field from the first Initial packet it sent in the initial_source_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0003">A server MUST include the Destination Connection ID field from the first Initial packet it received from the client in the original_destination_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0004">If it sends a Retry packet, a server MUST also include the Source Connection ID field from the Retry packet in the retry_source_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0009">If a zero-length connection ID is selected, the corresponding transport parameter MUST be included with a zero-length value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0005">A receiver MUST set initial limits for all streams through transport parameters during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0003">Initial limits MUST be set in the transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0005">Separate limits MUST apply to unidirectional and bidirectional streams.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6P1-0001">Servers MAY communicate a preferred address of each address family (IPv4 and IPv6) to allow clients to pick the one most suited to their network attachment.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6P1-0007">Servers MAY communicate a preferred address of each address family to allow clients to pick the one most suited to their network attachment.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18-0006")]
    [Requirement("REQ-QUIC-RFC9000-S18-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
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
    [Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0007")]
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0002">They MUST be encoded as a sequence of transport parameters, as shown in Figure 20:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0003">Each transport parameter MUST be encoded as an (identifier, length, value) tuple, as shown in Figure 21:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0004">The Transport Parameter ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0005">The Transport Parameter Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0006">The Transport Parameter Length field MUST contain the length of the Transport Parameter Value field in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0007">QUIC MUST encode transport parameters into a sequence of bytes, which is then included in the cryptographic handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0001">Transport parameters with an identifier of the form 31 * N + 27 for integer values of N MUST be reserved to exercise the requirement that unknown transport parameters be ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0002">These transport parameters have no semantics and MAY carry arbitrary values.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0001">This transport parameter MUST only be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0002">The maximum idle timeout is a value in milliseconds that MUST be encoded as an integer; see (Section 10.1).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0004">This transport parameter MAY be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0005">This transport parameter MUST NOT be sent by a client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0007">UDP datagrams with payloads larger than this limit MUST NOT be likely to be processed by the receiver.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0008">The initial maximum data parameter is an integer value that contains the initial value for the maximum amount of data that MAY be sent on the connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0010">The initial maximum bidirectional streams parameter is an integer value that MUST contain the initial maximum number of bidirectional streams the endpoint that receives this transport parameter is permitted to initiate.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0013">The initial maximum unidirectional streams parameter is an integer value that MUST contain the initial maximum number of unidirectional streams the endpoint that receives this transport parameter is permitted to initiate.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0015">This value SHOULD include the receiver&apos;s expected delays in alarms firing.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0016">The disable active migration transport parameter is included if the endpoint MUST NOT support active connection migration (Section 9) on the address being used during the handshake.</workbench-requirement>
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0001">The choice each endpoint makes about connection IDs during the handshake MUST be authenticated by including all values in transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0002">Each endpoint MUST include the value of the Source Connection ID field from the first Initial packet it sent in the initial_source_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0003">A server MUST include the Destination Connection ID field from the first Initial packet it received from the client in the original_destination_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0004">If it sends a Retry packet, a server MUST also include the Source Connection ID field from the Retry packet in the retry_source_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0009">If a zero-length connection ID is selected, the corresponding transport parameter MUST be included with a zero-length value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0005">A receiver MUST set initial limits for all streams through transport parameters during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0003">Initial limits MUST be set in the transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0005">Separate limits MUST apply to unidirectional and bidirectional streams.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6P1-0001">Servers MAY communicate a preferred address of each address family (IPv4 and IPv6) to allow clients to pick the one most suited to their network attachment.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6P1-0007">Servers MAY communicate a preferred address of each address family to allow clients to pick the one most suited to their network attachment.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18-0006")]
    [Requirement("REQ-QUIC-RFC9000-S18-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
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
    [Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0009")]
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

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S8-0001">The TLS handshake MUST carry values for QUIC transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0002">They MUST be encoded as a sequence of transport parameters, as shown in Figure 20:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0003">Each transport parameter MUST be encoded as an (identifier, length, value) tuple, as shown in Figure 21:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0004">The Transport Parameter ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0005">The Transport Parameter Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0006">The Transport Parameter Length field MUST contain the length of the Transport Parameter Value field in bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0007">QUIC MUST encode transport parameters into a sequence of bytes, which is then included in the cryptographic handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0001">Transport parameters with an identifier of the form 31 * N + 27 for integer values of N MUST be reserved to exercise the requirement that unknown transport parameters be ignored.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P1-0002">These transport parameters have no semantics and MAY carry arbitrary values.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0001">This transport parameter MUST only be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0002">The maximum idle timeout is a value in milliseconds that MUST be encoded as an integer; see (Section 10.1).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0004">This transport parameter MAY be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0005">This transport parameter MUST NOT be sent by a client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0007">UDP datagrams with payloads larger than this limit MUST NOT be likely to be processed by the receiver.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0008">The initial maximum data parameter is an integer value that contains the initial value for the maximum amount of data that MAY be sent on the connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0010">The initial maximum bidirectional streams parameter is an integer value that MUST contain the initial maximum number of bidirectional streams the endpoint that receives this transport parameter is permitted to initiate.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0013">The initial maximum unidirectional streams parameter is an integer value that MUST contain the initial maximum number of unidirectional streams the endpoint that receives this transport parameter is permitted to initiate.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0015">This value SHOULD include the receiver&apos;s expected delays in alarms firing.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0016">The disable active migration transport parameter is included if the endpoint MUST NOT support active connection migration (Section 9) on the address being used during the handshake.</workbench-requirement>
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
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0001">The choice each endpoint makes about connection IDs during the handshake MUST be authenticated by including all values in transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0002">Each endpoint MUST include the value of the Source Connection ID field from the first Initial packet it sent in the initial_source_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0003">A server MUST include the Destination Connection ID field from the first Initial packet it received from the client in the original_destination_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0004">If it sends a Retry packet, a server MUST also include the Source Connection ID field from the Retry packet in the retry_source_connection_id transport parameter.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0009">If a zero-length connection ID is selected, the corresponding transport parameter MUST be included with a zero-length value.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0005">A receiver MUST set initial limits for all streams through transport parameters during the handshake.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0003">Initial limits MUST be set in the transport parameters.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0005">Separate limits MUST apply to unidirectional and bidirectional streams.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6P1-0001">Servers MAY communicate a preferred address of each address family (IPv4 and IPv6) to allow clients to pick the one most suited to their network attachment.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P6P1-0007">Servers MAY communicate a preferred address of each address family to allow clients to pick the one most suited to their network attachment.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9001-S8-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18-0006")]
    [Requirement("REQ-QUIC-RFC9000-S18-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0013")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0015")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0016")]
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
    [Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_TransportParameters_RoundTripsRepresentativeValuesAndRejectsTruncation()
    {
        Random random = new(0x5150_2030);
        Span<byte> destination = stackalloc byte[256];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            QuicTransportParameters parameters = BuildRandomParameters(random);

            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Server,
                destination,
                out int bytesWritten));

            byte[] baseEncoded = destination[..bytesWritten].ToArray();
            byte[] encoded = baseEncoded;
            if ((iteration & 1) == 0)
            {
                byte[] greaseTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(
                    27,
                    new[] { (byte)random.Next(0, 256), (byte)random.Next(0, 256), (byte)random.Next(0, 256) });
                encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(baseEncoded, greaseTuple);
            }

            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                encoded,
                QuicTransportParameterRole.Client,
                out QuicTransportParameters parsed));

            AssertTransportParametersEqual(parameters, parsed);

            if (baseEncoded.Length > 1)
            {
                byte[] truncated = baseEncoded[..^1];

                Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
                    truncated,
                    QuicTransportParameterRole.Client,
                    out _));
            }
        }
    }

    private static QuicTransportParameters BuildRandomParameters(Random random)
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = RandomBytes(random, random.Next(0, 5)),
            MaxIdleTimeout = (ulong)random.Next(0, 4096),
            StatelessResetToken = RandomBytes(random, 16),
            MaxUdpPayloadSize = (ulong)random.Next(1200, 1600),
            InitialMaxData = (ulong)random.Next(0, 65536),
            InitialMaxStreamDataBidiLocal = (ulong)random.Next(0, 65536),
            InitialMaxStreamDataBidiRemote = (ulong)random.Next(0, 65536),
            InitialMaxStreamDataUni = (ulong)random.Next(0, 65536),
            InitialMaxStreamsBidi = (ulong)random.Next(0, 32),
            InitialMaxStreamsUni = (ulong)random.Next(0, 32),
            MaxAckDelay = (ulong)random.Next(0, 64),
            DisableActiveMigration = random.Next(0, 2) == 0,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = RandomBytes(random, 4),
                IPv4Port = (ushort)random.Next(0, ushort.MaxValue + 1),
                IPv6Address = RandomBytes(random, 16),
                IPv6Port = (ushort)random.Next(0, ushort.MaxValue + 1),
                ConnectionId = RandomBytes(random, random.Next(1, 6)),
                StatelessResetToken = RandomBytes(random, 16),
            },
            ActiveConnectionIdLimit = (ulong)random.Next(2, 64),
            InitialSourceConnectionId = RandomBytes(random, random.Next(0, 5)),
            RetrySourceConnectionId = RandomBytes(random, random.Next(0, 5)),
        };

        return parameters;
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] data = new byte[length];
        random.NextBytes(data);
        return data;
    }

    private static void AssertTransportParametersEqual(QuicTransportParameters expected, QuicTransportParameters actual)
    {
        Assert.True(expected.OriginalDestinationConnectionId!.AsSpan().SequenceEqual(actual.OriginalDestinationConnectionId!));
        Assert.Equal(expected.MaxIdleTimeout, actual.MaxIdleTimeout);
        Assert.True(expected.StatelessResetToken!.AsSpan().SequenceEqual(actual.StatelessResetToken!));
        Assert.Equal(expected.MaxUdpPayloadSize, actual.MaxUdpPayloadSize);
        Assert.Equal(expected.InitialMaxData, actual.InitialMaxData);
        Assert.Equal(expected.InitialMaxStreamDataBidiLocal, actual.InitialMaxStreamDataBidiLocal);
        Assert.Equal(expected.InitialMaxStreamDataBidiRemote, actual.InitialMaxStreamDataBidiRemote);
        Assert.Equal(expected.InitialMaxStreamDataUni, actual.InitialMaxStreamDataUni);
        Assert.Equal(expected.InitialMaxStreamsBidi, actual.InitialMaxStreamsBidi);
        Assert.Equal(expected.InitialMaxStreamsUni, actual.InitialMaxStreamsUni);
        Assert.Equal(expected.MaxAckDelay, actual.MaxAckDelay);
        Assert.Equal(expected.DisableActiveMigration, actual.DisableActiveMigration);
        Assert.NotNull(actual.PreferredAddress);
        Assert.True(expected.PreferredAddress!.IPv4Address.AsSpan().SequenceEqual(actual.PreferredAddress!.IPv4Address));
        Assert.Equal(expected.PreferredAddress.IPv4Port, actual.PreferredAddress.IPv4Port);
        Assert.True(expected.PreferredAddress.IPv6Address.AsSpan().SequenceEqual(actual.PreferredAddress.IPv6Address));
        Assert.Equal(expected.PreferredAddress.IPv6Port, actual.PreferredAddress.IPv6Port);
        Assert.True(expected.PreferredAddress.ConnectionId.AsSpan().SequenceEqual(actual.PreferredAddress.ConnectionId));
        Assert.True(expected.PreferredAddress.StatelessResetToken.AsSpan().SequenceEqual(actual.PreferredAddress.StatelessResetToken));
        Assert.Equal(expected.ActiveConnectionIdLimit, actual.ActiveConnectionIdLimit);
        Assert.True(expected.InitialSourceConnectionId!.AsSpan().SequenceEqual(actual.InitialSourceConnectionId!));
        Assert.True(expected.RetrySourceConnectionId!.AsSpan().SequenceEqual(actual.RetrySourceConnectionId!));
    }
}
