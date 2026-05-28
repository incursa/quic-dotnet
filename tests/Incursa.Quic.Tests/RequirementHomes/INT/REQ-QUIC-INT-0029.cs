// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0029")]
public sealed class REQ_QUIC_INT_0029
{
    private static readonly byte[] CapturedXquicClientTrafficSecret = Convert.FromHexString(
        // Captured from:
        // .artifacts\interop-runner\debug-client-transfer-xquic-current-after-docker-cleanup\20260522-221632093-client-chrome\
        //   runner-logs\xquic_chrome\transfer\client\keys.log
        // CLIENT_TRAFFIC_SECRET_0 for the focused xquic transfer rerun.
        "3B7857814E284143BC7F96BE24F877F74A050DF8A899AB8DEE97375886CC192D");

    private static readonly byte[] CapturedXquicServerConnectionId = Convert.FromHexString(
        // xquic server short-header destination connection ID from the same focused rerun.
        "AED10F5358CD237A3F767873");

    private static readonly byte[] CapturedXquicClientPacket13Protected = Convert.FromHexString(
        // Captured from:
        // .artifacts\interop-runner\debug-client-transfer-xquic-current-after-docker-cleanup\20260522-221632093-client-chrome\
        //   runner-logs\xquic_chrome\transfer\sim\trace_node_right.pcap
        // Enhanced-packet block 87: client -> xquic short-header 1-RTT packet with packet number 13.
        "44AED10F5358CD237A3F7678736E3C3C604C31779FCDC4E211B48992A6C12B8BD130A371D8914BCB9DA4A706EABD91" +
        "BB1C803AB2813137393B465FDA6DF73BA49FDAB711587D2C883717DCBD82F7B7D23DA73C95F51132F1A6285C86595076" +
        "A734D8660B2878809E09");

    private static readonly byte[][] CapturedXquicClientPackets14Through28Protected =
    [
        Convert.FromHexString(
            "51AED10F5358CD237A3F7678738327676ABF98A94A29C1D9BD64228780D064A8F66812D91263E1037767BCC36160327B" +
            "8F43D50268EA6C1C2883FF521126FD6B25126BE7AA17A82F61C6CC2ACC8E493255C2FFB938DE85F4D24976D4C9AF159F23"),
        Convert.FromHexString(
            "47AED10F5358CD237A3F7678737E8353FFF85A2C85279557FCC282C45F2C98DE0373D7A752662C22091A6694DFCF6560" +
            "778CE4E78D80D5CE315A37B4135750AD66CD74086FCEB6546CB2B58A467159D74529148A75D6FA6A1635B284DC2E2C220C"),
        Convert.FromHexString(
            "5AAED10F5358CD237A3F7678734EA3FF669D28E4EB3C04269B5D871CDFC78D71AD0119236A6619A921115A272DE1F40D" +
            "FAD1CCD236DC9E62DDD7924B0EB328AB925B77FA37A761E77FB69F1F10FB1FED65D6AE48C76F80A61F5CD6F1790E2AE8E1"),
        Convert.FromHexString(
            "42AED10F5358CD237A3F767873ED6FFACCEF83FD72D499678806E199D3474878D95FBBE05B23087410B7CFABAB196DBF" +
            "25A26333482051B1E822C4DCD36D5962EB07D6FE79CA63DF21C34A1598A8E4EAAEA3A81229B24CE1AFE91348A712A3DCB3"),
        Convert.FromHexString(
            "44AED10F5358CD237A3F767873B964B72C3591CBEA6666E527387062D5C9A304297C406A3131B6433995C76F1FA4581B" +
            "86CA973465FB1F6A0B8BF0DC732F984A8C2BEAC1251F090DE9C6D857C449C44A52A3D787FB5A662F35929002F5FEEB1071"),
        Convert.FromHexString(
            "58AED10F5358CD237A3F767873AA4D172AA24ED9E5452498EB56044AD16D4C21BBBE85D2D8DC4E993E0BC6BA72F6C7" +
            "DA059C88DFE4D151C62D6830838C60056B5385794CDC193AEE7903030877B48BA6897F80D8EAB91E14E460BDAD1028AA7CBF"),
        Convert.FromHexString(
            "51AED10F5358CD237A3F76787376D3FF6D86D023DECB309E4C9D4F7E27A545BEEC1B98A8F12290B6F2D680B82FFE028C" +
            "C0410FA020AB19126632952B801E65BD66AD72512E6B8666B89799E29D5FD2A0995890FE73AA3CB6DF3394AF00FB2D6695"),
        Convert.FromHexString(
            "48AED10F5358CD237A3F76787369834109DA52C3ECC9D29AB58EB82A1FAFA44FC8C8025B164052B294B08D303BFCE631" +
            "4CBF6ED0DC8839367CEB116DD2442D9943B3D8B547C3E465761C6E19711BDA3B567A865DCE24AB2A451BC6A3D7CE8E5BF7"),
        Convert.FromHexString(
            "54AED10F5358CD237A3F76787364296A1A7AD6DC976C07C4630184F67280A4676F0F132F36AC1DF3FB07FEFB438AD211" +
            "3422A13578D1EB82EB13EED2C7A265BE87492E12DC438C352E64471A7446B0159CCFEB6E6189EB9C33455FA120E6A43AC7"),
        Convert.FromHexString(
            "50AED10F5358CD237A3F767873B8A90488234DFA45869CBBD4077DA6DC794D61BCB315EC1C98B1E8DD1630B248CEDA3C" +
            "53C8CCF6C2970A84505F4808FFD5F6F153F8295DF8265D9DBCFD736F2AEC0D9B1E1E1FB866D0B257899EF0AAD94E422055"),
        Convert.FromHexString(
            "56AED10F5358CD237A3F767873AFBC633F559AAB1F39F4312262D678BA38553044EA8C88286C31E60DCE6E3764ECAFE" +
            "319E2CC867049CA2FB91271C64054022A45CEB3CDEC28B61BE96AE09012F71AA762764BC7ACD522106F3D3A963655878682"),
        Convert.FromHexString(
            "55AED10F5358CD237A3F767873B1AB45455262C5D8FCD85BADA8F9D87E8AC24686FB0B5B46B3628D87464438016CBC29" +
            "95913C7E8730C66BDD3707DC36FF0CAC8560FB64329132BBC0352A362022F451B7790312D5CA74C68C8D08585F44B776C0"),
        Convert.FromHexString(
            "55AED10F5358CD237A3F767873FB4D8A25AA3C0CE131367CC3236B96844C3655C95D558457A69C3CAB0D5AB63D772EBC" +
            "B628DF05C8426A39DD166A7EB6C67E796F669FBF91B7FF941C3CD2A46B79A1D02D7767919C362421C5B0420042C5771DFF"),
        Convert.FromHexString(
            "59AED10F5358CD237A3F767873DF5845BCFE1A0AAD078FEF814EC7DA8F5C3262362D234BEF10C5AD213C1060F71B2B7" +
            "18791D89E05CEDCB490D364060F451967B4625BFD66B28196E7777D0E0EB4FDC5D84FFBB7A9F3E5FB2863839C8A42C11075"),
        Convert.FromHexString(
            "5EAED10F5358CD237A3F7678733E3F33C4DB3A8720EF3BF01C0CC317BE3C5E0E2CB87B5D40F0D75FCA76A3A293F245" +
            "A2ED46D716AD5D5625A8308BC829AF23CF1F24698EF8644C720EBEE716006BBFFF844F987AB6A2CE3FF524A08E575AA35F0D"),
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void XquicResidualIsTraceOwnedBeforeRuntimePromotion()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string currentStatus = ReadRepositoryFile("docs/current-status.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0023.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0023.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0023.json");

        Assert.Contains("REQ-QUIC-INT-0029", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-INT-0023", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-INT-0023", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0023", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0029", gapLedger, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0029", currentStatus, StringComparison.Ordinal);
        Assert.Contains("debug-client-keyupdate-chacha20-xquic-live-refresh", currentStatus, StringComparison.Ordinal);
        Assert.Contains("15,355 bytes", currentStatus, StringComparison.Ordinal);
        Assert.Contains("debug-client-transfer-xquic-current-after-docker-cleanup", spec, StringComparison.Ordinal);
        Assert.Contains("debug-client-transfer-xquic-current-after-docker-cleanup", gapLedger, StringComparison.Ordinal);
        Assert.Contains("all-upstream-streamdata-keyupdate-local", architecture, StringComparison.Ordinal);
        Assert.Contains("xquic-specific ingress, packet-opening, or path-liveness investigation", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0029", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0029", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0029", verification, StringComparison.Ordinal);
        Assert.Contains("debug-client-transfer-xquic-live-refresh", verification, StringComparison.Ordinal);
        Assert.Contains("debug-client-keyupdate-chacha20-xquic-live-refresh", verification, StringComparison.Ordinal);
        Assert.Contains("all-upstream-streamdata-keyupdate-local", verification, StringComparison.Ordinal);
        Assert.Contains("35,400 bytes at the response-stream FIN boundary", verification, StringComparison.Ordinal);
        Assert.Contains("15,355 bytes", verification, StringComparison.Ordinal);
        Assert.Contains("stream_read_notify", verification, StringComparison.Ordinal);
        Assert.Contains("response burst running through packet 22", verification, StringComparison.Ordinal);
        Assert.Contains("pacing blocked", verification, StringComparison.Ordinal);
        Assert.Contains("stream_offset:16536", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedXquicPostBurstAckPacketOpensAndAcknowledgesResponsePacket17()
    {
        ReadOnlySpan<byte> payload = OpenCapturedXquicClientApplicationPayload(
            CapturedXquicClientPacket13Protected,
            out ulong packetNumber);

        Assert.Equal(13UL, packetNumber);
        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(17UL, ackFrame.LargestAcknowledged);
        Assert.Equal(67UL, ackFrame.AckDelay);
        Assert.Equal(4UL, ackFrame.FirstAckRange);

        QuicAckRange additionalRange = Assert.Single(ackFrame.AdditionalRanges);
        Assert.Equal(0UL, additionalRange.Gap);
        Assert.Equal(11UL, additionalRange.AckRangeLength);
        Assert.Equal(0UL, additionalRange.SmallestAcknowledged);
        Assert.Equal(11UL, additionalRange.LargestAcknowledged);

        ReadOnlySpan<byte> remaining = payload[ackBytesConsumed..];
        Assert.True(QuicFrameCodec.TryParseMaxDataFrame(
            remaining,
            out QuicMaxDataFrame maxDataFrame,
            out int maxDataBytesConsumed));
        Assert.Equal(16_779_580UL, maxDataFrame.MaximumData);

        AssertOnlyPadding(remaining[maxDataBytesConsumed..]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedXquicPostBurstCreditBurstPublishesRepeatedMaxDataAndMaxStreamData()
    {
        ulong[] expectedCreditValues =
        [
            16_779_580UL,
            16_780_761UL,
            16_781_942UL,
            16_786_038UL,
            16_787_847UL,
            16_789_028UL,
            16_790_209UL,
            16_791_390UL,
        ];
        List<ulong> observedMaxDataValues = [];
        List<ulong> observedMaxStreamDataValues = [];

        byte[][] protectedPackets =
        [
            CapturedXquicClientPacket13Protected,
            .. CapturedXquicClientPackets14Through28Protected,
        ];

        for (int index = 0; index < protectedPackets.Length; index++)
        {
            ReadOnlySpan<byte> payload = OpenCapturedXquicClientApplicationPayload(
                protectedPackets[index],
                out ulong packetNumber);
            Assert.Equal(13UL + (ulong)index, packetNumber);

            CapturedCreditFrame creditFrame = ReadSingleCapturedCreditFrame(payload);
            if (creditFrame.IsMaxData)
            {
                observedMaxDataValues.Add(creditFrame.MaximumData);
            }
            else
            {
                Assert.Equal(0UL, creditFrame.StreamId);
                observedMaxStreamDataValues.Add(creditFrame.MaximumStreamData);
            }
        }

        Assert.Equal(expectedCreditValues, observedMaxDataValues);
        Assert.Equal(expectedCreditValues, observedMaxStreamDataValues);
        AssertStrictlyIncreasing(observedMaxDataValues);
        AssertStrictlyIncreasing(observedMaxStreamDataValues);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void XquicResidualDoesNotWeakenTheAdvisoryBoundary()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0023.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0023.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0023.json");

        Assert.Contains("it is not HTTP/3, migration, server-role non-handshake, or support-readiness proof", gapLedger, StringComparison.Ordinal);
        Assert.Contains("avoiding converting mostly-green all-upstream evidence into broad support-readiness claims", spec, StringComparison.Ordinal);
        Assert.Contains("does not imply HTTP/3 or broader API support", architecture, StringComparison.Ordinal);
        Assert.Contains("runtime transport changes in this trace-ownership slice", workItem, StringComparison.Ordinal);
        Assert.Contains("does not claim xquic support", verification, StringComparison.Ordinal);
        Assert.DoesNotContain("xquic support is green", spec, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("support-readiness promotion", gapLedger, StringComparison.OrdinalIgnoreCase);
    }

    private static byte[] OpenCapturedXquicClientApplicationPayload(
        ReadOnlySpan<byte> protectedPacket,
        out ulong packetNumber)
    {
        Assert.True(QuicCapturedInteropTransferEvidence.TryCreateOneRttPacketProtectionMaterial(
            CapturedXquicClientTrafficSecret,
            out QuicTlsPacketProtectionMaterial openMaterial));

        QuicHandshakeFlowCoordinator coordinator = new(CapturedXquicServerConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            openMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));
        Assert.False(observedKeyPhase);

        int packetNumberOffset = 1 + CapturedXquicServerConnectionId.Length;
        int packetNumberLength = (openedPacket[0] & 0x03) + 1;
        Assert.Equal(sizeof(uint), packetNumberLength);
        packetNumber = BinaryPrimitives.ReadUInt32BigEndian(openedPacket.AsSpan(packetNumberOffset, packetNumberLength));
        return openedPacket.AsSpan(payloadOffset, payloadLength).ToArray();
    }

    private static void AssertOnlyPadding(ReadOnlySpan<byte> payload)
    {
        while (!payload.IsEmpty)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int paddingBytesConsumed));
            payload = payload[paddingBytesConsumed..];
        }
    }

    private static CapturedCreditFrame ReadSingleCapturedCreditFrame(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        CapturedCreditFrame? observedCreditFrame = null;

        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                AssertOnlyPadding(remaining);
                break;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseMaxDataFrame(remaining, out QuicMaxDataFrame maxDataFrame, out int maxDataBytesConsumed))
            {
                Assert.Null(observedCreditFrame);
                observedCreditFrame = CapturedCreditFrame.ForMaxData(maxDataFrame.MaximumData);
                offset += maxDataBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseMaxStreamDataFrame(
                    remaining,
                    out QuicMaxStreamDataFrame maxStreamDataFrame,
                    out int maxStreamDataBytesConsumed))
            {
                Assert.Null(observedCreditFrame);
                observedCreditFrame = CapturedCreditFrame.ForMaxStreamData(
                    maxStreamDataFrame.StreamId,
                    maxStreamDataFrame.MaximumStreamData);
                offset += maxStreamDataBytesConsumed;
                continue;
            }

            Assert.Fail($"Unexpected captured xquic application-data frame type 0x{remaining[0]:X2}.");
        }

        Assert.NotNull(observedCreditFrame);
        return observedCreditFrame.Value;
    }

    private static void AssertStrictlyIncreasing(IReadOnlyList<ulong> values)
    {
        for (int index = 1; index < values.Count; index++)
        {
            Assert.True(
                values[index] > values[index - 1],
                $"Expected {values[index]} at index {index} to be greater than {values[index - 1]}.");
        }
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        string repoRoot = FindRepoRoot();
        string candidate = Path.Combine(repoRoot, relativePath);
        if (File.Exists(candidate))
        {
            return File.ReadAllText(candidate);
        }

        throw new InvalidOperationException($"Unable to locate '{relativePath}' under '{repoRoot}'.");
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string gitMarker = Path.Combine(current.FullName, ".git");
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-INT.json");
            string gapMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "REQUIREMENT-GAPS.md");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(gapMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the xquic residual requirement home test.");
    }

    private readonly record struct CapturedCreditFrame(
        bool IsMaxData,
        ulong MaximumData,
        ulong StreamId,
        ulong MaximumStreamData)
    {
        public static CapturedCreditFrame ForMaxData(ulong maximumData)
        {
            return new CapturedCreditFrame(true, maximumData, 0, 0);
        }

        public static CapturedCreditFrame ForMaxStreamData(ulong streamId, ulong maximumStreamData)
        {
            return new CapturedCreditFrame(false, 0, streamId, maximumStreamData);
        }
    }
}
