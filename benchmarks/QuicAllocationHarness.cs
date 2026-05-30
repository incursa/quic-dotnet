// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

#pragma warning disable CA1416

using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using IncursaClientConnection = global::Incursa.Quic.QuicConnection;
using IncursaListener = global::Incursa.Quic.QuicListener;
using SystemNetClientConnection = global::System.Net.Quic.QuicConnection;
using SystemNetListener = global::System.Net.Quic.QuicListener;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Non-BDN allocation measurement harness that runs high-N connection iterations
/// and reports managed allocations, working-set, and private-bytes delta per iteration.
/// Runs two passes to distinguish warmup/cache effects from real per-connection retention.
///
/// Usage:
///   dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --harness [count]
///
/// Example:
///   dotnet run -c Release --project benchmarks/Incursa.Quic.Benchmarks.csproj -- --harness 5000
/// </summary>
internal static class QuicAllocationHarness
{
    private const int DefaultCount = 2000;
    private const int WarmupCount = 3;
    private const int PassCount = 2;

    internal static int Run(string[] args)
    {
        if (args is ["--help"])
        {
            Console.WriteLine();
            Console.WriteLine("QUIC Allocation Measurement Harness");
            Console.WriteLine();
            Console.WriteLine("  --harness N    Two-pass throughput + allocation measurement.");
            Console.WriteLine("                 Reports managed B/op, working set B/op, private bytes B/op.");
            Console.WriteLine("                 Runs both Incursa.Quic and System.Net.Quic.");
            Console.WriteLine("                 Default N=2000.  Example: --harness 10000");
            Console.WriteLine();
            Console.WriteLine("  --leak N       Live-then-dispose plateau test for native retention.");
            Console.WriteLine("                 Creates N connections, captures memory, disposes, waits,");
            Console.WriteLine("                 captures again.  Two batches distinguish warmup from leak.");
            Console.WriteLine("                 Tests System.Net.Quic only.  Default N=1000.");
            Console.WriteLine();
            Console.WriteLine("  --profile N    Run allocation profiler with EventListener.");
            Console.WriteLine("                 Reports top allocated types by size during Incursa.Quic");
            Console.WriteLine("                 connection establishment.  Default N=50.");
            Console.WriteLine();
            return 0;
        }

        int count = DefaultCount;
        if (args.Length > 1 && int.TryParse(args[1], out int parsed) && parsed > 0)
        {
            count = parsed;
        }

        if (args is ["--leak", ..])
        {
            return RunLeakTest(count);
        }

        if (args is ["--profile", ..])
        {
            return RunAllocationProfile(count);
        }

        return RunAllocationHarness(count);
    }

    private static int RunAllocationHarness(int count)
    {
        Console.WriteLine();
        Console.WriteLine("=== QUIC Allocation Harness ===");
        Console.WriteLine($"Iterations per pass: {count:N0}");
        Console.WriteLine("Passes: 2");
        Console.WriteLine();

        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);

        try
        {
            if (IncursaClientConnection.IsSupported && IncursaListener.IsSupported)
            {
                Console.WriteLine("--- Incursa.Quic ---");
                for (int pass = 1; pass <= PassCount; pass++)
                {
                    RunPass($"  pass {pass}/{PassCount}", count,
                        () => RunIncursaConnectAcceptDisposeAsync(serverAuthOptions, clientAuthOptions)
                            .GetAwaiter().GetResult());
                }

                Console.WriteLine();
            }

            if (SystemNetClientConnection.IsSupported && SystemNetListener.IsSupported)
            {
                Console.WriteLine("--- System.Net.Quic ---");
                for (int pass = 1; pass <= PassCount; pass++)
                {
                    RunPass($"  pass {pass}/{PassCount}", count,
                        () => RunSystemNetConnectAcceptDisposeAsync(serverAuthOptions, clientAuthOptions)
                            .GetAwaiter().GetResult());
                }

                Console.WriteLine();
            }
        }
        finally
        {
            trustAnchor.Dispose();
            serverCertificate.Dispose();
        }

        Console.WriteLine("=== End ===");
        Console.WriteLine();
        return 0;
    }

    /// <summary>
    /// Runs the allocation profile: breaks Incursa.Quic connect/accept/dispose into phases
    /// and reports the managed allocation contributed by each phase per operation.
    /// </summary>
    private static int RunAllocationProfile(int count)
    {
        Console.WriteLine();
        Console.WriteLine("=== QUIC Phase Allocation Profile ===");
        Console.WriteLine($"Iterations: {count:N0}");
        Console.WriteLine("Measures managed allocation per lifecycle phase via GC.GetTotalAllocatedBytes");
        Console.WriteLine();

        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);

        // Accumulators per phase
        var phaseTotals = new Dictionary<string, long>
        {
            ["listener"] = 0,
            ["connect+accept"] = 0,
            ["close+dispose"] = 0,
        };

        static long Snap() => GC.GetTotalAllocatedBytes(precise: true);

        // Warmup
        for (int i = 0; i < 3; i++)
        {
            RunIncursaProfileOnce(serverAuthOptions, clientAuthOptions, ref phaseTotals, Snap);
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        foreach (var key in phaseTotals.Keys) phaseTotals[key] = 0;

        for (int i = 0; i < count; i++)
        {
            RunIncursaProfileOnce(serverAuthOptions, clientAuthOptions, ref phaseTotals, Snap);
        }

        Console.WriteLine($"  {"Phase",-25} {"Total (B)",12} {"B/op",10} {"% of total",10}");
        Console.WriteLine($"  {"-----",-25} {"---------",12} {"----",10} {"---------",10}");

        long grandTotal = phaseTotals.Values.Sum();
        foreach (var kv in phaseTotals.OrderByDescending(kv => kv.Value))
        {
            double pct = grandTotal > 0 ? (double)kv.Value / grandTotal * 100 : 0;
            Console.WriteLine($"  {kv.Key,-25} {kv.Value,12:N0} {kv.Value / count,10:N0} {pct,8:F1}%");
        }

        Console.WriteLine($"  {"-----",-25} {"---------",12} {"----",10}");
        Console.WriteLine($"  {"TOTAL",-25} {grandTotal,12:N0} {grandTotal / count,10:N0}");

        // Compare to harness total
        long harnessTotal = Snap();
        Console.WriteLine();
        Console.WriteLine($"  Phase total:    {grandTotal,12:N0} B  ({grandTotal / count,10:N0} B/op)");
        Console.WriteLine($"  Harness total:  {(Snap() - harnessTotal) + grandTotal,12:N0} B  (includes certificate/options overhead)");
        Console.WriteLine();

        trustAnchor.Dispose();
        serverCertificate.Dispose();
        return 0;
    }

    /// <summary>
    /// Runs one Incursa.Quic connect/accept/dispose with per-phase allocation tracking.
    /// </summary>
    private static void RunIncursaProfileOnce(
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions,
        ref Dictionary<string, long> phaseTotals,
        Func<long> snap)
    {
        long before = snap();

        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();
        var listener = IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(listenEndPoint, serverOptions))
            .GetAwaiter().GetResult();

        phaseTotals["listener"] += snap() - before;

        before = snap();
        var acceptTask = listener.AcceptConnectionAsync().AsTask();
        var connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port), clientOptions)).AsTask();

        Task.WhenAll(acceptTask, connectTask).GetAwaiter().GetResult();
        var serverConnection = acceptTask.GetAwaiter().GetResult();
        var clientConnection = connectTask.GetAwaiter().GetResult();
        phaseTotals["connect+accept"] += snap() - before;

        before = snap();
        serverConnection.CloseAsync(0, CancellationToken.None).GetAwaiter().GetResult();
        clientConnection.CloseAsync(0, CancellationToken.None).GetAwaiter().GetResult();
        serverConnection.DisposeAsync().GetAwaiter().GetResult();
        clientConnection.DisposeAsync().GetAwaiter().GetResult();
        listener.DisposeAsync().GetAwaiter().GetResult();
        phaseTotals["close+dispose"] += snap() - before;
    }

    private static int RunLeakTest(int count)
    {
        Console.WriteLine();
        Console.WriteLine("=== QUIC Plateau / Retention Test ===");
        Console.WriteLine($"Connections per batch: {count:N0}");
        Console.WriteLine("Tests System.Net.Quic — memory growth after Close+Dispose");
        Console.WriteLine();

        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);

        try
        {
            Console.WriteLine("--- System.Net.Quic plateau test ---");

            if (!SystemNetClientConnection.IsSupported || !SystemNetListener.IsSupported)
            {
                Console.WriteLine("System.Net.Quic is not supported on this platform.");
                return 0;
            }

            for (int batch = 1; batch <= 2; batch++)
            {
                Console.WriteLine();
                Console.WriteLine($"Batch {batch}/2 — creating {count} connections...");
                RunLeakBatch(count, serverAuthOptions, clientAuthOptions).GetAwaiter().GetResult();
            }
        }
        finally
        {
            trustAnchor.Dispose();
            serverCertificate.Dispose();
        }

        return 0;
    }

    private static async Task RunLeakBatch(
        int count,
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions)
    {
        var connections = new List<SystemNetClientConnection>(count * 2);

        long managedStart, wsStart, privStart;
        Snapshot(out managedStart, out wsStart, out privStart);

        for (int i = 0; i < count; i++)
        {
            var (client, server) = await CreateSystemNetConnectedPairAsync(serverOptions, clientOptions);
            connections.Add(client);
            connections.Add(server);
        }

        long managedLive, wsLive, privLive;
        Snapshot(out managedLive, out wsLive, out privLive);
        Console.WriteLine($"  live:     managed={managedLive - managedStart,12:N0} B  ws={wsLive - wsStart,12:N0} B  priv={privLive - privStart,12:N0} B");

        foreach (SystemNetClientConnection conn in connections)
        {
            await conn.CloseAsync(0, CancellationToken.None);
            await conn.DisposeAsync();
        }
        connections.Clear();

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        await Task.Delay(TimeSpan.FromSeconds(10));

        long managedEnd, wsEnd, privEnd;
        Snapshot(out managedEnd, out wsEnd, out privEnd);
        Console.WriteLine($"  after close+dispose+10s:");
        Console.WriteLine($"    managed delta from live:  {managedEnd - managedLive,12:N0} B");
        Console.WriteLine($"    ws delta from live:       {wsEnd - wsLive,12:N0} B");
        Console.WriteLine($"    priv delta from live:     {privEnd - privLive,12:N0} B");
        Console.WriteLine($"    retained from baseline:   priv={privEnd - privStart,12:N0} B  ws={wsEnd - wsStart,12:N0} B");
        Console.WriteLine($"    retained/conn:            priv={(privEnd - privStart) / count,10:N0} B  ws={(wsEnd - wsStart) / count,10:N0} B");
    }

    private static void Snapshot(out long managed, out long workingSet, out long privateBytes)
    {
        var process = Process.GetCurrentProcess();
        process.Refresh();
        managed = GC.GetTotalAllocatedBytes(precise: true);
        workingSet = process.WorkingSet64;
        privateBytes = process.PrivateMemorySize64;
    }

    private static void RunPass(string label, int count, Action operation)
    {
        // Warmup — settle JIT and early allocations
        for (int i = 0; i < WarmupCount; i++)
        {
            operation();
        }

        // Forced GC settle before measurement
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var process = Process.GetCurrentProcess();
        process.Refresh();

        long startManaged = GC.GetTotalAllocatedBytes(precise: true);
        long startWorkingSet = process.WorkingSet64;
        long startPrivateBytes = process.PrivateMemorySize64;
        long startStopwatch = Stopwatch.GetTimestamp();

        for (int i = 0; i < count; i++)
        {
            operation();
        }

        process.Refresh();
        long endStopwatch = Stopwatch.GetTimestamp();
        long endManaged = GC.GetTotalAllocatedBytes(precise: true);
        long endWorkingSet = process.WorkingSet64;
        long endPrivateBytes = process.PrivateMemorySize64;

        double elapsedSec = (double)(endStopwatch - startStopwatch) / Stopwatch.Frequency;
        long managedDelta = endManaged - startManaged;
        long wsDelta = endWorkingSet - startWorkingSet;
        long privDelta = endPrivateBytes - startPrivateBytes;

        Console.WriteLine(
            $"  {label, -28}" +
            $"{count,6:N0} iters  {elapsedSec,7:N3}s  {elapsedSec / count * 1000,8:N3} ms/op");
        Console.WriteLine(
            $"  {"",-28}" +
            $"managed: {managedDelta / (double)count,10:N0} B/op  " +
            $"ws: {wsDelta / (double)count,10:N0} B/op  " +
            $"priv: {privDelta / (double)count,10:N0} B/op");
    }

    private static async Task RunIncursaConnectAcceptDisposeAsync(
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions)
    {
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(
                listenEndPoint, serverOptions)).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientOptions)).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);

        IncursaClientConnection serverConnection = await acceptTask.ConfigureAwait(false);
        IncursaClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await serverConnection.CloseAsync(0, CancellationToken.None).ConfigureAwait(false);
        await clientConnection.CloseAsync(0, CancellationToken.None).ConfigureAwait(false);
        await serverConnection.DisposeAsync().ConfigureAwait(false);
        await clientConnection.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task<(SystemNetClientConnection Client, SystemNetClientConnection Server)> CreateSystemNetConnectedPairAsync(
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions)
    {
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(
                listenEndPoint, serverOptions)).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientOptions)).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);

        SystemNetClientConnection server = await acceptTask.ConfigureAwait(false);
        SystemNetClientConnection client = await connectTask.ConfigureAwait(false);
        return (client, server);
    }

    private static async Task RunSystemNetConnectAcceptDisposeAsync(
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions)
    {
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        await using SystemNetListener listener = await SystemNetListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetListenerOptions(
                listenEndPoint, serverOptions)).ConfigureAwait(false);

        Task<SystemNetClientConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<SystemNetClientConnection> connectTask = SystemNetClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateSystemNetClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientOptions)).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);

        SystemNetClientConnection serverConnection = await acceptTask.ConfigureAwait(false);
        SystemNetClientConnection clientConnection = await connectTask.ConfigureAwait(false);

        await serverConnection.CloseAsync(0, CancellationToken.None);
        await clientConnection.CloseAsync(0, CancellationToken.None);
        await serverConnection.DisposeAsync().ConfigureAwait(false);
        await clientConnection.DisposeAsync().ConfigureAwait(false);
    }
}
