// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicReceiveBufferPoolTests
{
    [Fact]
    public void Rent_UsesRingBeforeFallback()
    {
        using QuicReceiveBufferPool pool = new(bufferSize: 32, ringSize: 2);

        using QuicReceiveBufferLease first = pool.Rent();
        using QuicReceiveBufferLease second = pool.Rent();
        using QuicReceiveBufferLease third = pool.Rent();

        QuicReceiveBufferPoolSnapshot snapshot = pool.Snapshot;

        Assert.Equal(2, snapshot.RingRents);
        Assert.Equal(1, snapshot.FallbackRents);
        Assert.Equal(3, snapshot.CurrentOutstanding);
        Assert.Equal(3, snapshot.MaxOutstanding);
        Assert.True(first.Ownership.FromRing);
        Assert.True(second.Ownership.FromRing);
        Assert.False(third.Ownership.FromRing);
    }

    [Fact]
    public void Dispose_ReturnsBuffersExactlyOnce()
    {
        using QuicReceiveBufferPool pool = new(bufferSize: 32, ringSize: 1);
        QuicReceiveBufferLease lease = pool.Rent();

        lease.Dispose();
        lease.Dispose();

        QuicReceiveBufferPoolSnapshot snapshot = pool.Snapshot;

        Assert.Equal(1, snapshot.Returns);
        Assert.Equal(0, snapshot.CurrentOutstanding);
        Assert.Equal(0, snapshot.DoubleReturnAttempts);
    }

    [Fact]
    public void Return_IgnoresDuplicateRingBufferReturn()
    {
        using QuicReceiveBufferPool pool = new(bufferSize: 32, ringSize: 1);
        QuicReceiveBufferLease lease = pool.Rent();
        byte[] buffer = lease.Buffer;
        QuicReceiveBufferOwnership ownership = lease.Ownership;

        lease.Dispose();
        pool.Return(buffer, ownership);

        QuicReceiveBufferPoolSnapshot snapshot = pool.Snapshot;

        Assert.Equal(1, snapshot.Returns);
        Assert.Equal(0, snapshot.CurrentOutstanding);
        Assert.Equal(1, snapshot.DoubleReturnAttempts);
    }

    [Fact]
    public void Constructor_UsesEnvironmentRingSizeWhenNoExplicitRingSizeIsProvided()
    {
        string? original = Environment.GetEnvironmentVariable(QuicReceiveBufferPool.RingSizeEnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable(QuicReceiveBufferPool.RingSizeEnvironmentVariable, "3");
            using QuicReceiveBufferPool pool = new(bufferSize: 32);

            Assert.Equal(3, pool.Snapshot.RingSize);
        }
        finally
        {
            Environment.SetEnvironmentVariable(QuicReceiveBufferPool.RingSizeEnvironmentVariable, original);
        }
    }

    [Fact]
    public void Dispose_WritesDiagnosticSnapshotWhenPathIsConfigured()
    {
        string path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.jsonl");
        string? original = Environment.GetEnvironmentVariable(QuicReceiveBufferPoolDiagnostics.SnapshotPathEnvironmentVariable);
        try
        {
            Environment.SetEnvironmentVariable(QuicReceiveBufferPoolDiagnostics.SnapshotPathEnvironmentVariable, path);
            using (QuicReceiveBufferPool pool = new(bufferSize: 32, ringSize: 1, ownerName: "test"))
            {
                using QuicReceiveBufferLease lease = pool.Rent();
            }

            string line = File.ReadAllLines(path).Single(line => line.Contains("\"reason\":\"dispose\"", StringComparison.Ordinal));
            Assert.Contains("\"reason\":\"dispose\"", line, StringComparison.Ordinal);
            Assert.Contains("\"ownerName\":\"test\"", line, StringComparison.Ordinal);
            Assert.Contains("\"ringSize\":1", line, StringComparison.Ordinal);
            Assert.Contains("\"ringRents\":1", line, StringComparison.Ordinal);
            Assert.Contains("\"fallbackRents\":0", line, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(QuicReceiveBufferPoolDiagnostics.SnapshotPathEnvironmentVariable, original);
            File.Delete(path);
        }
    }
}
