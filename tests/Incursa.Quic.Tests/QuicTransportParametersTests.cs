namespace Incursa.Quic.Tests;

public sealed class QuicTransportParametersTests
{
    [Fact]
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
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0002")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S4P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0003")]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0005")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P6P1-0007")]
    [Trait("Category", "Positive")]
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
    [Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
    [Trait("Category", "Negative")]
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

    [Theory]
    [MemberData(nameof(MatchingConnectionIdBindingCases))]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0006")]
    [Trait("Category", "Positive")]
    public void TryValidateConnectionIdBindings_AcceptsMatchingConnectionIdBindings(
        QuicTransportParameterRole receiverRole,
        byte[] initialDestinationConnectionId,
        byte[] initialSourceConnectionId,
        bool usedRetry,
        byte[] retrySourceConnectionId,
        QuicTransportParameters peerParameters)
    {
        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            receiverRole,
            initialDestinationConnectionId,
            initialSourceConnectionId,
            usedRetry,
            retrySourceConnectionId,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);
    }

    [Theory]
    [MemberData(nameof(MissingConnectionIdBindingCases))]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0007")]
    [Trait("Category", "Negative")]
    public void TryValidateConnectionIdBindings_RejectsMissingConnectionIdBindings(
        QuicTransportParameterRole receiverRole,
        byte[] initialDestinationConnectionId,
        byte[] initialSourceConnectionId,
        bool usedRetry,
        byte[] retrySourceConnectionId,
        QuicTransportParameters peerParameters,
        QuicConnectionIdBindingValidationError expectedError)
    {
        Assert.False(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            receiverRole,
            initialDestinationConnectionId,
            initialSourceConnectionId,
            usedRetry,
            retrySourceConnectionId,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(expectedError, validationError);
    }

    [Theory]
    [MemberData(nameof(MismatchedConnectionIdBindingCases))]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0008")]
    [Trait("Category", "Negative")]
    public void TryValidateConnectionIdBindings_RejectsMismatchedConnectionIdBindings(
        QuicTransportParameterRole receiverRole,
        byte[] initialDestinationConnectionId,
        byte[] initialSourceConnectionId,
        bool usedRetry,
        byte[] retrySourceConnectionId,
        QuicTransportParameters peerParameters,
        QuicConnectionIdBindingValidationError expectedError)
    {
        Assert.False(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            receiverRole,
            initialDestinationConnectionId,
            initialSourceConnectionId,
            usedRetry,
            retrySourceConnectionId,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(expectedError, validationError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0020")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0021")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0022")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0023")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0028")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0029")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0030")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0031")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0032")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0033")]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0002")]
    public void TryParseTransportParameters_AcceptsPreferredAddressWithZeroedIpv4Family()
    {
        QuicTransportParameters parameters = new()
        {
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [0, 0, 0, 0],
                IPv4Port = 0,
                IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                IPv6Port = 8443,
                ConnectionId = [0xAA, 0xBB],
                StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x90 + value)).ToArray(),
            },
        };

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        QuicPreferredAddress preferredAddress = parsed.PreferredAddress!;
        Assert.True(new byte[] { 0, 0, 0, 0 }.AsSpan().SequenceEqual(preferredAddress.IPv4Address));
        Assert.Equal((ushort)0, preferredAddress.IPv4Port);
        Assert.True(new byte[] { 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06 }.AsSpan().SequenceEqual(preferredAddress.IPv6Address));
        Assert.Equal((ushort)8443, preferredAddress.IPv6Port);
        Assert.True(new byte[] { 0xAA, 0xBB }.AsSpan().SequenceEqual(preferredAddress.ConnectionId));
        Assert.True(new byte[] { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F }.AsSpan().SequenceEqual(preferredAddress.StatelessResetToken));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18-0006")]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsTruncatedTupleValue()
    {
        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25));
        byte[] truncated = tuple[..^1];

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            truncated,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S7P4P2-0001")]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_IgnoresReservedGreaseParameters()
    {
        byte[] greaseTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xDE, 0xAD, 0xBE, 0xEF]);
        byte[] maxIdleTimeoutTuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25));
        byte[] block = QuicTransportParameterTestData.BuildTransportParameterBlock(greaseTuple, maxIdleTimeoutTuple);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            block,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.Equal(25UL, parsed.MaxIdleTimeout);
        Assert.Null(parsed.OriginalDestinationConnectionId);
        Assert.Null(parsed.StatelessResetToken);
        Assert.Null(parsed.PreferredAddress);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P4-0002")]
    [Requirement("REQ-QUIC-RFC9000-S7P4-0003")]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsDuplicateTransportParameters()
    {
        byte[] duplicateKnownParameter = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(33)));

        byte[] duplicateUnknownParameter = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xAA]),
            QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xBB]));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            duplicateKnownParameter,
            QuicTransportParameterRole.Client,
            out _));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            duplicateUnknownParameter,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0037")]
    [Trait("Category", "Negative")]
    public void TryFormatTransportParameters_RejectsServerOnlyParametersWhenSendingAsClient()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = [0x01, 0x02],
            StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x30 + value)).ToArray(),
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                IPv6Port = 8443,
                ConnectionId = [0xAA],
                StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x40 + value)).ToArray(),
            },
            RetrySourceConnectionId = [0x10, 0x11],
        };

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            stackalloc byte[128],
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0038")]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsServerOnlyParametersWhenReceivingAsServer()
    {
        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x02, Enumerable.Range(0, 16).Select(value => (byte)(0x50 + value)).ToArray());

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            tuple,
            QuicTransportParameterRole.Server,
            out _));
    }

    [Fact]
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
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsPreferredAddressWithZeroLengthConnectionId()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: [192, 0, 2, 1],
            ipv4Port: 443,
            ipv6Address: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
            ipv6Port: 8443,
            connectionId: [],
            statelessResetToken: Enumerable.Range(0, 16).Select(value => (byte)(0x60 + value)).ToArray());

        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            tuple,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0035")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0036")]
    [Requirement("REQ-QUIC-RFC9000-S7P4-0001")]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsActiveConnectionIdLimitBelowTwo()
    {
        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x0E, QuicVarintTestData.EncodeMinimal(1));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            tuple,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0019")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0020")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0021")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0022")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0023")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0028")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0029")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0030")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0031")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0032")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0033")]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsTruncatedPreferredAddressValue()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: [192, 0, 2, 1],
            ipv4Port: 443,
            ipv6Address: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
            ipv6Port: 8443,
            connectionId: [0xAA, 0xBB],
            statelessResetToken: Enumerable.Range(0, 16).Select(value => (byte)(0x70 + value)).ToArray());

        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue);
        byte[] truncated = tuple[..^1];

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            truncated,
            QuicTransportParameterRole.Client,
            out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
    [Trait("Category", "Negative")]
    public void TryFormatAndParseTransportParameters_RejectsInitialMaxStreamsAboveTheLimit()
    {
        QuicTransportParameters boundaryParameters = new()
        {
            InitialMaxStreamsBidi = 1UL << 60,
            InitialMaxStreamsUni = 1UL << 60,
        };

        Span<byte> boundaryDestination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            boundaryParameters,
            QuicTransportParameterRole.Server,
            boundaryDestination,
            out int boundaryBytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            boundaryDestination[..boundaryBytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters boundaryParsed));
        Assert.Equal(1UL << 60, boundaryParsed.InitialMaxStreamsBidi);
        Assert.Equal(1UL << 60, boundaryParsed.InitialMaxStreamsUni);

        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsBidi = (1UL << 60) + 1,
            InitialMaxStreamsUni = (1UL << 60) + 1,
        };

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            stackalloc byte[64],
            out _));

        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x08,
            QuicVarintTestData.EncodeMinimal((1UL << 60) + 1));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            tuple,
            QuicTransportParameterRole.Client,
            out _));
    }
}
