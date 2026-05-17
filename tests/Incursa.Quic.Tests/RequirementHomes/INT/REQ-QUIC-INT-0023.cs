using System.Text;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0023")]
public sealed class REQ_QUIC_INT_0023
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicGoDownloadLivenessSliceUsesTheKnownBodyLengthCompletionBoundary()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string currentStatus = ReadRepositoryFile("docs/current-status.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0017.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0017.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0017.json");

        Assert.Contains("REQ-QUIC-INT-0023", spec, StringComparison.Ordinal);
        Assert.Contains("quic-go client download-liveness", spec, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ARC-QUIC-INT-0017", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-INT-0017", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0017", spec, StringComparison.Ordinal);
        Assert.Contains("interop-quic-go-client-download-liveness", gapLedger, StringComparison.Ordinal);
        Assert.Contains("formalized as `REQ-QUIC-INT-0023`", gapLedger, StringComparison.Ordinal);
        Assert.Contains("quic-go` client `transfer` and `keyupdate`", gapLedger, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0023", currentStatus, StringComparison.Ordinal);
        Assert.Contains("quic-go client `transfer`/`keyupdate` drain path", currentStatus, StringComparison.Ordinal);
        Assert.Contains("known mounted source-length body", currentStatus, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("download completion on the mounted source-length body", architecture, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("downloads against the mounted source-length body", workItem, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("bounded source-length completion contract", verification, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("REQ-QUIC-INT-0023", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task QuicGoDownloadLivenessBodyCopyCompletesAtTheExpectedLengthWithoutWaitingForPeerEof()
    {
        byte[] payload = Encoding.UTF8.GetBytes($"quic-go download-liveness body {Guid.NewGuid():N}");
        using BoundedResponseStream responseStream = new(payload, failOnReadAfterExpectedLength: true);
        using MemoryStream destinationStream = new();

        long bytesCopied = await InteropHarnessRunner.CopyHttp09ResponseBodyAsync(
            responseStream,
            destinationStream,
            payload.Length,
            TextWriter.Null,
            "transfer",
            configuredRequestCount: 1,
            requestIndex: 0,
            totalRequestCount: 1,
            requestPath: "/download-liveness",
            responseReadTimeout: Timeout.InfiniteTimeSpan);

        Assert.Equal(payload.Length, bytesCopied);
        Assert.Equal(payload, destinationStream.ToArray());
        Assert.Equal(0, responseStream.ReadsAfterExpectedLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task QuicGoDownloadLivenessBodyCopyFailsWhenThePeerClosesBeforeTheExpectedLength()
    {
        byte[] payload = Encoding.UTF8.GetBytes($"short download-liveness body {Guid.NewGuid():N}");
        using BoundedResponseStream responseStream = new(payload, prematureEndAfterBytes: payload.Length - 1);
        using MemoryStream destinationStream = new();

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await InteropHarnessRunner.CopyHttp09ResponseBodyAsync(
                responseStream,
                destinationStream,
                payload.Length,
                TextWriter.Null,
                "transfer",
                configuredRequestCount: 1,
                requestIndex: 0,
                totalRequestCount: 1,
                requestPath: "/download-liveness",
                responseReadTimeout: Timeout.InfiniteTimeSpan));

        Assert.Contains("expected body length", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(payload.Length, destinationStream.ToArray().Length);
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
            string helperMarker = Path.Combine(current.FullName, "scripts", "interop", "Invoke-QuicInteropRunner.ps1");
            if (Directory.Exists(gitMarker) && File.Exists(specMarker) && File.Exists(helperMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the quic-go download-liveness requirement home test.");
    }

    private sealed class BoundedResponseStream : Stream
    {
        private readonly byte[] payload;
        private readonly long? prematureEndAfterBytes;
        private readonly bool failOnReadAfterExpectedLength;
        private int position;

        public BoundedResponseStream(
            byte[] payload,
            long? prematureEndAfterBytes = null,
            bool failOnReadAfterExpectedLength = false)
        {
            this.payload = payload ?? throw new ArgumentNullException(nameof(payload));
            this.prematureEndAfterBytes = prematureEndAfterBytes;
            this.failOnReadAfterExpectedLength = failOnReadAfterExpectedLength;
        }

        public int ReadsAfterExpectedLength { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => payload.Length;

        public override long Position
        {
            get => position;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            ArgumentNullException.ThrowIfNull(buffer);
            if (offset < 0 || count < 0 || offset > buffer.Length - count)
            {
                throw new ArgumentOutOfRangeException();
            }

            return ReadCore(buffer.AsSpan(offset, count));
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(ReadCore(buffer.Span));

        private int ReadCore(Span<byte> buffer)
        {
            long availableBytes = prematureEndAfterBytes ?? payload.Length;
            if (position >= availableBytes)
            {
                return 0;
            }

            if (position >= payload.Length)
            {
                ReadsAfterExpectedLength++;
                if (failOnReadAfterExpectedLength)
                {
                    throw new InvalidOperationException("Unexpected extra read beyond the expected body length.");
                }

                return 0;
            }

            int count = (int)Math.Min(buffer.Length, Math.Min(payload.Length - position, availableBytes - position));
            payload.AsSpan(position, count).CopyTo(buffer);
            position += count;
            return count;
        }
    }
}
