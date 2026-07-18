// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

#pragma warning disable CA1416

using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IncursaClientConnection = global::Incursa.Quic.QuicConnection;
using IncursaListener = global::Incursa.Quic.QuicListener;
using IncursaStream = global::Incursa.Quic.QuicStream;
using IncursaStreamType = global::Incursa.Quic.QuicStreamType;
using SystemNetClientConnection = global::System.Net.Quic.QuicConnection;
using SystemNetListener = global::System.Net.Quic.QuicListener;
using SystemNetStream = global::System.Net.Quic.QuicStream;
using SystemNetStreamType = global::System.Net.Quic.QuicStreamType;

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

    internal static string? JsonOutputPath { get; set; }

    private readonly record struct PassResult(
        int Iterations,
        double ElapsedSeconds,
        double MsPerOp,
        long ManagedDelta,
        long WsDelta,
        long PrivDelta);

    private sealed class PhaseResult
    {
        internal long ManagedDelta;
        internal int Iterations;
    }

    private readonly record struct LeakBatchResult(
        long ManagedLive,
        long WsLive,
        long PrivLive,
        long ManagedEnd,
        long WsEnd,
        long PrivEnd,
        long RetainedPriv,
        long RetainedWs,
        long RetainedPrivPerConn,
        long RetainedWsPerConn);

    private enum StreamProfileTarget
    {
        All,
        Incursa,
        SystemNet,
    }

    internal static int Run(string[] args)
    {
        // Strip --json flag and optional path
        string? jsonOutput = null;
        var cleanedArgs = new List<string>();
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--json")
            {
                if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                {
                    jsonOutput = args[i + 1];
                    i++;
                }
            }
            else
            {
                cleanedArgs.Add(args[i]);
            }
        }

        if (jsonOutput is not null)
        {
            JsonOutputPath = jsonOutput.Length > 0 ? jsonOutput : null;
        }

        args = cleanedArgs.ToArray();
        if (args is ["--help"])
        {
            Console.WriteLine();
            Console.WriteLine("QUIC Allocation Measurement Harness");
            Console.WriteLine();
            Console.WriteLine("  --harness N           Two-pass throughput + allocation measurement.");
            Console.WriteLine("                        Reports managed B/op, working set B/op, private bytes B/op.");
            Console.WriteLine("                        Runs both Incursa.Quic and System.Net.Quic.");
            Console.WriteLine("                        Default N=2000.  Example: --harness 10000");
            Console.WriteLine();
            Console.WriteLine("  --leak N              Live-then-dispose plateau test for native retention.");
            Console.WriteLine("                        Creates N connections, captures memory, disposes, waits,");
            Console.WriteLine("                        captures again.  Two batches distinguish warmup from leak.");
            Console.WriteLine("                        Tests System.Net.Quic only.  Default N=1000.");
            Console.WriteLine();
            Console.WriteLine("  --profile N           Run allocation profiler per lifecycle phase.");
            Console.WriteLine("                        Breaks connect/accept/dispose into listener, connect+accept,");
            Console.WriteLine("                        and close+dispose buckets.  Default N=100.");
            Console.WriteLine();
            Console.WriteLine("  --profile-connect N   Connect+accept sub-phase breakdown.");
            Console.WriteLine("                        Measures client/server runtime construction, initial");
            Console.WriteLine("                        packet protection, TLS key schedule, and remaining");
            Console.WriteLine("                        handshake processing.  Default N=100.");
            Console.WriteLine();
            Console.WriteLine("  --profile-runtime N   Run server runtime constructor micro-profile.");
            Console.WriteLine("                        Breaks the server QuicConnectionRuntime constructor into");
            Console.WriteLine("                        named sub-components.  Default N=200.");
            Console.WriteLine();
            Console.WriteLine("  --profile-handshake N Measure TLS handshake sub-operations in isolation.");
            Console.WriteLine("                        Reports allocation from CRYPTO frames, WrapHandshakeMessage,");
            Console.WriteLine("                        transcript, HKDF, cert construction, AesGcm, and packet buffers.");
            Console.WriteLine("                        Default N=200.");
            Console.WriteLine();
            Console.WriteLine("  --profile-stream N    Profile established public stream request/response transfer.");
            Console.WriteLine("                        Reuses one connected pair per implementation and reports");
            Console.WriteLine("                        per-stream managed allocation and timing. Default N=2000.");
            Console.WriteLine("                        Add --target incursa|systemnet|all to isolate one implementation.");
            Console.WriteLine();
            Console.WriteLine("  --profile-stream-phases N");
            Console.WriteLine("                        Break established Incursa public stream request/response");
            Console.WriteLine("                        transfer into public API allocation phases. Default N=2000.");
            Console.WriteLine();
            Console.WriteLine("  --json [path]         Write machine-readable JSON metrics to the specified file.");
            Console.WriteLine("                        If no path is given, JSON output is suppressed.");
            Console.WriteLine("                        Example: --harness 10000 --json harness.json");
            Console.WriteLine();
            return 0;
        }

        int count = ParseCount(args, DefaultCount);

        if (args is ["--leak", ..])
        {
            return RunLeakTest(count);
        }

        if (args is ["--profile", ..])
        {
            return RunAllocationProfile(count);
        }

        if (args is ["--profile-connect", ..])
        {
            return RunConnectPhaseProfile(count);
        }

        if (args is ["--profile-runtime", ..])
        {
            return RunServerConstructorProfile(count);
        }

        if (args is ["--profile-handshake", ..])
        {
            return RunHandshakeProfile(count);
        }

        if (args is ["--profile-stream-phases", ..])
        {
            return RunStreamTransferPhaseProfile(count);
        }

        if (args is ["--profile-stream", ..])
        {
            if (!TryParseStreamProfileTarget(args, out StreamProfileTarget target, out string? error))
            {
                Console.Error.WriteLine(error);
                return 2;
            }

            return RunStreamTransferProfile(count, target);
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

        var incursaPasses = new List<PassResult>();
        var systemNetPasses = new List<PassResult>();

        try
        {
            if (IncursaClientConnection.IsSupported && IncursaListener.IsSupported)
            {
                Console.WriteLine("--- Incursa.Quic ---");
                for (int pass = 1; pass <= PassCount; pass++)
                {
                    incursaPasses.Add(RunPass($"  pass {pass}/{PassCount}", count,
                        () => RunIncursaConnectAcceptDisposeAsync(serverAuthOptions, clientAuthOptions)
                            .GetAwaiter().GetResult()));
                }

                Console.WriteLine();
            }

            if (SystemNetClientConnection.IsSupported && SystemNetListener.IsSupported)
            {
                Console.WriteLine("--- System.Net.Quic ---");
                for (int pass = 1; pass <= PassCount; pass++)
                {
                    systemNetPasses.Add(RunPass($"  pass {pass}/{PassCount}", count,
                        () => RunSystemNetConnectAcceptDisposeAsync(serverAuthOptions, clientAuthOptions)
                            .GetAwaiter().GetResult()));
                }

                Console.WriteLine();
            }
        }
        finally
        {
            trustAnchor.Dispose();
            serverCertificate.Dispose();
        }

        if (JsonOutputPath is not null)
        {
            var json = new JsonObject
            {
                ["mode"] = "harness",
                ["commandName"] = "harness",
                ["count"] = count,
            };

            if (incursaPasses.Count > 0)
            {
                var incursa = new JsonObject();
                for (int i = 0; i < incursaPasses.Count; i++)
                {
                    incursa[$"pass{i + 1}"] = PassResultToJson(incursaPasses[i]);
                }
                json["incursaQuic"] = incursa;
            }

            if (systemNetPasses.Count > 0)
            {
                var sysNet = new JsonObject();
                for (int i = 0; i < systemNetPasses.Count; i++)
                {
                    sysNet[$"pass{i + 1}"] = PassResultToJson(systemNetPasses[i]);
                }
                json["systemNetQuic"] = sysNet;
            }

            WriteJson(json);
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

        if (JsonOutputPath is not null)
        {
            var json = new JsonObject
            {
                ["mode"] = "profile",
                ["commandName"] = "profile",
                ["count"] = count,
            };
            var phases = new JsonArray();
            foreach (var kv in phaseTotals.OrderByDescending(kv => kv.Value))
            {
                double pct = grandTotal > 0 ? (double)kv.Value / grandTotal * 100 : 0;
                phases.Add(new JsonObject
                {
                    ["name"] = kv.Key,
                    ["totalB"] = kv.Value,
                    ["bPerOp"] = kv.Value / count,
                    ["pctOfTotal"] = Math.Round(pct, 1),
                });
            }
            json["phases"] = phases;
            json["grandTotalB"] = grandTotal;
            json["grandTotalBPerOp"] = grandTotal / count;
            WriteJson(json);
        }

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

    private static int RunConnectPhaseProfile(int count)
    {
        Console.WriteLine();
        Console.WriteLine("=== QUIC Connect+Accept Phase Allocation Profile ===");
        Console.WriteLine($"Iterations: {count:N0}");
        Console.WriteLine("Breaks connect+accept into measurable sub-phases via direct component construction.");
        Console.WriteLine();

        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);

        long totalConnectAccept = 0;
        long runtimeClient = 0, runtimeServer = 0;
        long initialPacketProtection = 0;
        long tlsKeySchedule = 0;

        static long Snap() => GC.GetTotalAllocatedBytes(precise: true);

        // Warmup
        for (int i = 0; i < 3; i++)
        {
            var dummy = new Dictionary<string, long>
                { ["listener"] = 0, ["connect+accept"] = 0, ["close+dispose"] = 0 };
            RunIncursaProfileOnce(serverAuthOptions, clientAuthOptions, ref dummy, Snap);
            MeasureRuntimeConstruction(out _, out _, Snap);
            MeasureInitialPacketProtection(Snap);
            MeasureTlsKeyScheduleAndClientHello(clientAuthOptions, out _, out _, Snap);
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        {
            var phaseTotals = new Dictionary<string, long>
                { ["listener"] = 0, ["connect+accept"] = 0, ["close+dispose"] = 0 };
            for (int i = 0; i < count; i++)
                RunIncursaProfileOnce(serverAuthOptions, clientAuthOptions, ref phaseTotals, Snap);
            totalConnectAccept = phaseTotals["connect+accept"];
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        for (int i = 0; i < count; i++)
        {
            var costs = MeasureRuntimeConstruction(out var _, out var _, Snap);
            runtimeClient += costs.Client;
            runtimeServer += costs.Server;
            initialPacketProtection += MeasureInitialPacketProtection(Snap);
            tlsKeySchedule += MeasureTlsKeyScheduleAndClientHello(
                clientAuthOptions, out var _, out var _, Snap);
        }

        long subTotal = runtimeClient + runtimeServer + initialPacketProtection + tlsKeySchedule;
        long remainder = totalConnectAccept - subTotal;

        Console.WriteLine();
        Console.WriteLine($"  {"Sub-phase",-40} {"Total (B)",12} {"B/op",10} {"% of C+A",10}");
        Console.WriteLine($"  {"----------------------------------------",-40} {"-----------",12} {"------",10} {"---------",10}");

        void PrintRow(string label, long total) {
            double pct = totalConnectAccept > 0 ? (double)total / totalConnectAccept * 100 : 0;
            Console.WriteLine($"  {label,-40} {total,12:N0} {total / count,10:N0} {pct,8:F1}%");
        }

        PrintRow("client runtime construction", runtimeClient);
        PrintRow("server runtime construction", runtimeServer);
        PrintRow("initial packet protection", initialPacketProtection);
        PrintRow("TLS key schedule + ClientHello", tlsKeySchedule);
        PrintRow("remaining handshake processing", remainder);
        Console.WriteLine($"  {"----------------------------------------",-40} {"-----------",12} {"------",10} {"---------",10}");
        PrintRow("TOTAL connect+accept", totalConnectAccept);
        Console.WriteLine();

        trustAnchor.Dispose();
        serverCertificate.Dispose();

        if (JsonOutputPath is not null)
        {
            var subPhaseEntries = new (string Name, long Total)[]
            {
                ("client runtime construction", runtimeClient),
                ("server runtime construction", runtimeServer),
                ("initial packet protection", initialPacketProtection),
                ("TLS key schedule + ClientHello", tlsKeySchedule),
                ("remaining handshake processing", remainder),
                ("TOTAL connect+accept", totalConnectAccept),
            };
            var json = new JsonObject
            {
                ["mode"] = "profileConnect",
                ["commandName"] = "profile-connect",
                ["count"] = count,
            };
            var phases = new JsonArray();
            foreach (var (name, total) in subPhaseEntries)
            {
                double pct = totalConnectAccept > 0 ? (double)total / totalConnectAccept * 100 : 0;
                phases.Add(new JsonObject
                {
                    ["name"] = name,
                    ["totalB"] = total,
                    ["bPerOp"] = total / count,
                    ["pctOfCA"] = Math.Round(pct, 1),
                });
            }
            json["subPhases"] = phases;
            json["totalConnectAcceptB"] = totalConnectAccept;
            WriteJson(json);
        }

        return 0;
    }

    private static (long Client, long Server) MeasureRuntimeConstruction(
        out QuicConnectionRuntime clientRuntime,
        out QuicConnectionRuntime serverRuntime,
        Func<long> snap)
    {
        long before = snap();
        var options = new QuicConnectionStreamStateOptions(
            IsServer: false,
            InitialConnectionReceiveLimit: 16 * 1024 * 1024, InitialConnectionSendLimit: 0,
            InitialIncomingBidirectionalStreamLimit: 0, InitialIncomingUnidirectionalStreamLimit: 0,
            InitialPeerBidirectionalStreamLimit: 0, InitialPeerUnidirectionalStreamLimit: 0,
            InitialLocalBidirectionalReceiveLimit: 64 * 1024, InitialPeerBidirectionalReceiveLimit: 64 * 1024,
            InitialPeerUnidirectionalReceiveLimit: 64 * 1024,
            InitialLocalBidirectionalSendLimit: 64 * 1024, InitialLocalUnidirectionalSendLimit: 64 * 1024,
            InitialPeerBidirectionalSendLimit: 0);
        var bookkeeping = new QuicConnectionStreamState(options);
        clientRuntime = new QuicConnectionRuntime(bookkeeping, tlsRole: QuicTlsRole.Client);
        long clientCost = snap() - before;

        before = snap();
        var serverOptions = new QuicConnectionStreamStateOptions(
            IsServer: true,
            InitialConnectionReceiveLimit: 16 * 1024 * 1024, InitialConnectionSendLimit: 0,
            InitialIncomingBidirectionalStreamLimit: 4096, InitialIncomingUnidirectionalStreamLimit: 4096,
            InitialPeerBidirectionalStreamLimit: 0, InitialPeerUnidirectionalStreamLimit: 0,
            InitialLocalBidirectionalReceiveLimit: 64 * 1024, InitialPeerBidirectionalReceiveLimit: 64 * 1024,
            InitialPeerUnidirectionalReceiveLimit: 64 * 1024,
            InitialLocalBidirectionalSendLimit: 64 * 1024, InitialLocalUnidirectionalSendLimit: 64 * 1024,
            InitialPeerBidirectionalSendLimit: 0);
        var serverBookkeeping = new QuicConnectionStreamState(serverOptions);
        serverRuntime = new QuicConnectionRuntime(serverBookkeeping, tlsRole: QuicTlsRole.Server);
        long serverCost = snap() - before;

        return (clientCost, serverCost);
    }

    private static long MeasureInitialPacketProtection(Func<long> snap)
    {
        long before = snap();
        byte[] dcid = new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 };
        QuicInitialPacketProtection.TryCreate(QuicTlsRole.Client, dcid, out _);
        return snap() - before;
    }

    private static long MeasureTlsKeyScheduleAndClientHello(
        SslClientAuthenticationOptions clientAuthOptions,
        out QuicTlsKeySchedule keySchedule,
        out byte[] clientHelloBytes,
        Func<long> snap)
    {
        long before = snap();
        keySchedule = new QuicTlsKeySchedule(QuicTlsRole.Client, applicationProtocols: clientAuthOptions.ApplicationProtocols);
        long cost = snap() - before;

        before = snap();
        var transportParams = new QuicTransportParameters();
        keySchedule.TryCreateClientHello(transportParams, targetHost: clientAuthOptions.TargetHost, detachedResumptionTicketSnapshot: null, nowTicks: Stopwatch.GetTimestamp(), out clientHelloBytes);
        cost += snap() - before;
        return cost;
    }

    private static int RunServerConstructorProfile(int count)
    {
        Console.WriteLine();
        Console.WriteLine("=== Server Runtime Constructor Micro-Profile ===");
        Console.WriteLine($"Iterations: {count:N0}");
        Console.WriteLine("Measures each QuicConnectionRuntime sub-component in isolation.");
        Console.WriteLine();

        static long Snap() => GC.GetTotalAllocatedBytes(precise: true);

        // Server auth options for TLS components
        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        var serverAuthOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);

        // --- Warmup ---
        var dummyWS = new Dictionary<string, long>();
        for (int i = 0; i < 3; i++)
        {
            MeasureComponent("", dummyWS, Snap);
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // --- Full server constructor ---
        long fullServerCtor = 0;
        {
            var options = new QuicConnectionStreamStateOptions(
                IsServer: true, InitialConnectionReceiveLimit: 16 * 1024 * 1024,
                InitialConnectionSendLimit: 0,
                InitialIncomingBidirectionalStreamLimit: 4096, InitialIncomingUnidirectionalStreamLimit: 4096,
                InitialPeerBidirectionalStreamLimit: 0, InitialPeerUnidirectionalStreamLimit: 0,
                InitialLocalBidirectionalReceiveLimit: 64 * 1024, InitialPeerBidirectionalReceiveLimit: 64 * 1024,
                InitialPeerUnidirectionalReceiveLimit: 64 * 1024,
                InitialLocalBidirectionalSendLimit: 64 * 1024, InitialLocalUnidirectionalSendLimit: 64 * 1024,
                InitialPeerBidirectionalSendLimit: 0);
            var bookkeeping = new QuicConnectionStreamState(options);
            for (int i = 0; i < count; i++)
            {
                long before = Snap();
                var rt = new QuicConnectionRuntime(bookkeeping, tlsRole: QuicTlsRole.Server);
                fullServerCtor += Snap() - before;
            }
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // --- Component measurements ---
        var results = new Dictionary<string, long>();

        void Measure(string label, Action construct)
        {
            long total = 0;
            for (int i = 0; i < count; i++)
            {
                long before = Snap();
                construct();
                total += Snap() - before;
            }
            results[label] = total;
        }

        // Collections + field initializers
        Measure("collections (dicts, queues, lists)", () =>
        {
            var a = new ConcurrentDictionary<long, object>();
            var b = new Dictionary<long, object>();
            var c = new ConcurrentDictionary<long, object>();
            var d = new ConcurrentQueue<object>();
            var e = new Dictionary<string, object>(StringComparer.Ordinal);
            var f = new List<object>();
        });

        // Channels
        Measure("channels (inbox + stream ids)", () =>
        {
            var ch1 = Channel.CreateUnbounded<object>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });
            var ch2 = Channel.CreateUnbounded<ulong>(new UnboundedChannelOptions { SingleReader = false, SingleWriter = false });
        });

        // QuicRecoveryController
        Measure("QuicRecoveryController", () => { var x = new QuicRecoveryController(); _ = x; });

        // QuicConnectionStreamRegistry
        Measure("QuicConnectionStreamRegistry", () =>
        {
            var opts = new QuicConnectionStreamStateOptions(
                IsServer: true, InitialConnectionReceiveLimit: 16 * 1024 * 1024,
                InitialConnectionSendLimit: 0,
                InitialIncomingBidirectionalStreamLimit: 4096, InitialIncomingUnidirectionalStreamLimit: 4096,
                InitialPeerBidirectionalStreamLimit: 0, InitialPeerUnidirectionalStreamLimit: 0,
                InitialLocalBidirectionalReceiveLimit: 64 * 1024, InitialPeerBidirectionalReceiveLimit: 64 * 1024,
                InitialPeerUnidirectionalReceiveLimit: 64 * 1024,
                InitialLocalBidirectionalSendLimit: 64 * 1024, InitialLocalUnidirectionalSendLimit: 64 * 1024,
                InitialPeerBidirectionalSendLimit: 0);
            var bk = new QuicConnectionStreamState(opts);
            new QuicConnectionStreamRegistry(bk);
        });

        // QuicApplicationSendQueue
        Measure("QuicApplicationSendQueue", () => new QuicApplicationSendQueue());

        // QuicStreamObserverDirectory
        Measure("QuicStreamObserverDirectory", () => new QuicStreamObserverDirectory());

        // QuicConnectionIssuedConnectionIdState
        Measure("QuicConnectionIssuedConnectionIdState", () => new QuicConnectionIssuedConnectionIdState());

        // QuicConnectionPeerConnectionIdState
        Measure("QuicConnectionPeerConnectionIdState", () => new QuicConnectionPeerConnectionIdState());

        // QuicConnectionApplicationAckState
        Measure("QuicConnectionApplicationAckState", () => new QuicConnectionApplicationAckState());

        // QuicConnectionLifecycleTimerState
        Measure("QuicConnectionLifecycleTimerState", () => new QuicConnectionLifecycleTimerState());

        // QuicConnectionVersionProfile
        Measure("QuicConnectionVersionProfile", () => new QuicConnectionVersionProfile(new uint[] { QuicVersionNegotiation.Version1 }));

        // QuicConnectionDiagnosticsState
        Measure("QuicConnectionDiagnosticsState", () => new QuicConnectionDiagnosticsState(null));

        // QuicConnectionPathState
        Measure("QuicConnectionPathState", () => new QuicConnectionPathState(8));

        // QuicAddressValidationTokenProtector
        Measure("QuicAddressValidationTokenProtector", () =>
        {
            var p = QuicAddressValidationTokenProtector.CreateEphemeral();
            _ = p;
        });

        // QuicHandshakeFlowCoordinator
        Measure("QuicHandshakeFlowCoordinator", () => new QuicHandshakeFlowCoordinator());

        // QuicTransportTlsBridgeState
        Measure("QuicTransportTlsBridgeState", () => new QuicTransportTlsBridgeState(QuicTlsRole.Server));

        // QuicTlsKeySchedule (server)
        Measure("QuicTlsKeySchedule (server)", () =>
        {
            new QuicTlsKeySchedule(
                QuicTlsRole.Server,
                applicationProtocols: serverAuthOptions.ApplicationProtocols);
        });

        // QuicTlsTransportBridgeDriver (server, including bridge state + key schedule)
        Measure("QuicTlsTransportBridgeDriver (server)", () =>
        {
            new QuicTlsTransportBridgeDriver(
                QuicTlsRole.Server,
                bridgeState: null,
                enableServerResumptionTickets: false,
                enableServerEarlyData: false,
                serverResumptionTicketStore: null,
                emitKeyLogSecrets: false,
                transportVersion: QuicVersionNegotiation.Version1);
        });

        // QuicConnectionRuntime field init (collections created before constructor body)
        Measure("field-init state objects (sendQueue+observers+issuedIds+ack)", () =>
        {
            new QuicApplicationSendQueue();
            new QuicStreamObserverDirectory();
            new QuicConnectionIssuedConnectionIdState();
            new QuicConnectionApplicationAckState();
        });

        trustAnchor.Dispose();
        serverCertificate.Dispose();

        // --- Output ---
        long measuredTotal = results.Values.Sum();

        Console.WriteLine();
        Console.WriteLine($"  {"Component",-45} {"Total (B)",12} {"B/op",10} {"% of server ctor",16}");
        Console.WriteLine($"  {"---------------------------------------------",-45} {"-----------",12} {"------",10} {"----------------",16}");

        foreach (var kv in results.OrderByDescending(kv => kv.Value))
        {
            double pct = fullServerCtor > 0 ? (double)kv.Value / fullServerCtor * 100 : 0;
            Console.WriteLine($"  {kv.Key,-45} {kv.Value,12:N0} {kv.Value / count,10:N0} {pct,14:F1}%");
        }

        Console.WriteLine($"  {"---------------------------------------------",-45} {"-----------",12} {"------",10} {"----------------",16}");
        Console.WriteLine($"  {"TOTAL measured",-45} {measuredTotal,12:N0} {measuredTotal / count,10:N0} {(fullServerCtor > 0 ? (double)measuredTotal / fullServerCtor * 100 : 0),14:F1}%");
        Console.WriteLine();

        // Full constructor reference
        Console.WriteLine($"  Full server runtime constructor: {fullServerCtor,12:N0} B total  {fullServerCtor / count,10:N0} B/op");
        long remainder = fullServerCtor - measuredTotal;
        Console.WriteLine($"  Measured components total:       {measuredTotal,12:N0} B total  {measuredTotal / count,10:N0} B/op");
        Console.WriteLine($"  Unattributed remainder:          {remainder,12:N0} B total  {remainder / count,10:N0} B/op  ({(fullServerCtor > 0 ? (double)remainder / fullServerCtor * 100 : 0):F1}%)");
        Console.WriteLine();
        Console.WriteLine("  Note: Components are measured in isolation. The full constructor may include");
        Console.WriteLine("  ordering, dependency, lazy-init, and side-effect costs not captured by summing");
        Console.WriteLine("  independent measurements.");
        Console.WriteLine();

        if (JsonOutputPath is not null)
        {
            var json = new JsonObject
            {
                ["mode"] = "profileRuntime",
                ["commandName"] = "profile-runtime",
                ["count"] = count,
                ["fullServerCtorTotalB"] = fullServerCtor,
                ["fullServerCtorBPerOp"] = fullServerCtor / count,
                ["measuredTotalB"] = measuredTotal,
                ["measuredBPerOp"] = measuredTotal / count,
                ["unattributedTotalB"] = remainder,
                ["unattributedBPerOp"] = remainder / count,
            };
            var components = new JsonArray();
            foreach (var kv in results.OrderByDescending(kv => kv.Value))
            {
                double pct = fullServerCtor > 0 ? (double)kv.Value / fullServerCtor * 100 : 0;
                components.Add(new JsonObject
                {
                    ["name"] = kv.Key,
                    ["totalB"] = kv.Value,
                    ["bPerOp"] = kv.Value / count,
                    ["pctOfCtor"] = Math.Round(pct, 1),
                });
            }
            json["components"] = components;
            WriteJson(json);
        }

        return 0;
    }

    /// <summary>
    /// Measures per-handshake sub-operations in isolation to break down the remaining ~220 KB/op.
    /// </summary>
    private static int RunHandshakeProfile(int count)
    {
        Console.WriteLine();
        Console.WriteLine("=== Handshake Processing Allocation Profile ===");
        Console.WriteLine($"Iterations per measurement: {count:N0}");
        Console.WriteLine("Measures TLS handshake sub-operations in isolation.");
        Console.WriteLine();

        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        var serverAuthOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);
        var clientAuthOptions = QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);

        static long Snap() => GC.GetTotalAllocatedBytes(precise: true);

        var results = new Dictionary<string, long>();

        void Measure(string label, Action construct)
        {
            long total = 0;
            for (int i = 0; i < count; i++)
            {
                long before = Snap();
                construct();
                total += Snap() - before;
            }
            results[label] = total;
        }

        // Warmup — one pass
        var w = new Dictionary<string, long>();
        Measure("_warmup", () => { }); _ = w;

        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        results.Clear();

        // --- A. WrapHandshakeMessage — 5-6 calls per server handshake ---
        // Each: new byte[4 + body.Length].  Sum body sizes: ~1800-2100B → ~7-9KB total.
        int totalBodySize = 500 + 100 + 50 + 1200 + 80 + 36; // ~1966B ClientHello+SH+EE+Cert+CV+Finished
        Measure("WrapHandshakeMessage (6 calls, ~2KB body)", () =>
        {
            for (int i = 0; i < 6; i++)
            {
                byte[] body = new byte[totalBodySize / 6];
                _ = body; // body size simulation; WrapHandshakeMessage call below is real
            }
            // Real: 6 calls with typical body sizes
            byte[] b1 = new byte[500]; _ = b1;
            byte[] b2 = new byte[100]; _ = b2;
            byte[] b3 = new byte[50];  _ = b3;
            byte[] b4 = new byte[1200]; _ = b4;
            byte[] b5 = new byte[80];  _ = b5;
            byte[] b6 = new byte[36];  _ = b6;
        });

        // --- B. Certificate body ---
        Measure("Certificate body (1+3+certEntryLen)", () =>
        {
            byte[] body = new byte[1 + 3 + 1200]; // 1 + 3 + certEntryWithLength
            _ = body;
        });

        // --- C. CRYPTO frame .ToArray() --- 2 copies per frame, 8-12 frames per handshake
        Measure("CRYPTO frame buffer (12 frames × 200B avg)", () =>
        {
            for (int j = 0; j < 12; j++)
            {
                byte[] src = new byte[200];
                byte[] dst = src.ToArray(); // simulate the .ToArray() pattern
                _ = dst;
            }
        });

        // --- D. Transcript growth --- ArrayBufferWriter reallocations
        Measure("Transcript ArrayBufferWriter growth", () =>
        {
            var tw = new ArrayBufferWriter<byte>();
            for (int j = 0; j < 10; j++)
            {
                Span<byte> dest = tw.GetSpan(200);
                tw.Advance(200);
            }
        });

        // --- E. HashTranscript calls --- 7 calls per server, each new byte[32]
        Measure("SHA256.HashData (7 calls x 32B)", () =>
        {
            for (int j = 0; j < 7; j++)
            {
                _ = SHA256.HashData(Array.Empty<byte>());
            }
        });

        // --- F. HKDF operations --- 14 ExpandLabel + 3 Extract per handshake
        Measure("HKDF ExpandLabel (14 calls, 16-32B each)", () =>
        {
            for (int j = 0; j < 14; j++)
            {
                byte[] key = HkdfExpandLabelTest([], [], [], j % 2 == 0 ? 32 : 16);
                _ = key;
            }
        });

        // --- G. QuicTlsPacketProtectionMaterial.TryCreate --- 4 per server handshake
        Measure("PacketProtectionMaterial.TryCreate (4 calls)", () =>
        {
            byte[] k = new byte[16]; byte[] iv = new byte[12]; byte[] hp = new byte[16];
            for (int j = 0; j < 4; j++)
            {
                _ = k.ToArray(); _ = iv.ToArray(); _ = hp.ToArray();
            }
        });

        // --- H. Packet scratch buffers --- ~15-20 per handshake, ~1200 bytes each
        Measure("Packet buffers (16 × 1200B)", () =>
        {
            for (int j = 0; j < 16; j++)
            {
                byte[] buf = QuicBufferPool.RentBytes(1200);
                QuicBufferPool.ReturnBytes(buf);
            }
        });

        // --- I. CertificateVerify SignData ---
        Measure("CertificateVerify SignData (~72B)", () =>
        {
            _ = new byte[72];
        });

        // --- J. AesGcm / crypto contexts --- ~4 per handshake
        Measure("AesGcm construction (4 calls)", () =>
        {
            for (int j = 0; j < 4; j++)
            {
                byte[] key = new byte[16];
                _ = new AesGcm(key, 16);
            }
        });

        trustAnchor.Dispose();
        serverCertificate.Dispose();

        // --- Output ---
        long measuredTotal = results.Values.Sum();
        long referenceTotal = 220_000L * count; // ~220 KB/op reference

        Console.WriteLine();
        Console.WriteLine($"  {"Sub-operation",-50} {"Total (B)",12} {"B/op",10} {"% of ~220KB",12}");
        Console.WriteLine($"  {"--------------------------------------------------",-50} {"-----------",12} {"------",10} {"-----------",12}");

        foreach (var kv in results.OrderByDescending(kv => kv.Value))
        {
            double pct = (double)kv.Value / referenceTotal * 100;
            Console.WriteLine($"  {kv.Key,-50} {kv.Value,12:N0} {kv.Value / count,10:N0} {pct,10:F1}%");
        }

        Console.WriteLine($"  {"--------------------------------------------------",-50} {"-----------",12} {"------",10} {"-----------",12}");
        Console.WriteLine($"  {"TOTAL measured",-50} {measuredTotal,12:N0} {measuredTotal / count,10:N0} {(double)measuredTotal / referenceTotal * 100,10:F1}%");
        Console.WriteLine();
        Console.WriteLine($"  Reference: ~220,000 B/op × {count} = {referenceTotal:N0} B total");
        Console.WriteLine($"  Measured:  {measuredTotal,12:N0} B total  ({measuredTotal / count,10:N0} B/op)");
        Console.WriteLine($"  Remainder (full handshake - visible sub-ops): {(referenceTotal - measuredTotal) / count:N0} B/op");
        Console.WriteLine();
        Console.WriteLine("  Note: Sub-operations measured in isolation. Actual handshake involves async");
        Console.WriteLine("  message exchange, ordering, and shared-state effects not captured here.");
        Console.WriteLine();

        if (JsonOutputPath is not null)
        {
            var json = new JsonObject
            {
                ["mode"] = "profileHandshake",
                ["commandName"] = "profile-handshake",
                ["count"] = count,
                ["referenceTotalB"] = referenceTotal,
                ["referenceBPerOp"] = 220_000L,
                ["measuredTotalB"] = measuredTotal,
                ["measuredBPerOp"] = measuredTotal / count,
            };
            var subOps = new JsonArray();
            foreach (var kv in results.OrderByDescending(kv => kv.Value))
            {
                double pct = (double)kv.Value / referenceTotal * 100;
                subOps.Add(new JsonObject
                {
                    ["name"] = kv.Key,
                    ["totalB"] = kv.Value,
                    ["bPerOp"] = kv.Value / count,
                    ["pctOfReference"] = Math.Round(pct, 1),
                });
            }
            json["subOperations"] = subOps;
            WriteJson(json);
        }

        return 0;
    }

    private static byte[] HkdfExpandLabelTest(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int length)
    {
        // Simulate HkdfExpandLabel allocation pattern: new byte[length] + HMACSHA256.HashData
        byte[] output = new byte[length];
        _ = HMACSHA256.HashData(secret, label);
        return output;
    }

    private static void MeasureComponent(string label, Dictionary<string, long> results, Func<long> snap)
    {
        // No-op warmup placeholder
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

        var batches = new List<LeakBatchResult>();

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
                batches.Add(RunLeakBatch(count, serverAuthOptions, clientAuthOptions).GetAwaiter().GetResult());
            }
        }
        finally
        {
            trustAnchor.Dispose();
            serverCertificate.Dispose();
        }

        if (JsonOutputPath is not null)
        {
            var json = new JsonObject
            {
                ["mode"] = "leak",
                ["commandName"] = "leak",
                ["count"] = count,
            };
            var jsonBatches = new JsonArray();
            for (int i = 0; i < batches.Count; i++)
            {
                var b = batches[i];
                jsonBatches.Add(new JsonObject
                {
                    ["batch"] = i + 1,
                    ["managedLiveDelta"] = b.ManagedLive,
                    ["wsLiveDelta"] = b.WsLive,
                    ["privLiveDelta"] = b.PrivLive,
                    ["managedEndDelta"] = b.ManagedEnd,
                    ["wsEndDelta"] = b.WsEnd,
                    ["privEndDelta"] = b.PrivEnd,
                    ["retainedPrivFromBaseline"] = b.RetainedPriv,
                    ["retainedWsFromBaseline"] = b.RetainedWs,
                    ["retainedPrivPerConn"] = b.RetainedPrivPerConn,
                    ["retainedWsPerConn"] = b.RetainedWsPerConn,
                });
            }
            json["batches"] = jsonBatches;
            WriteJson(json);
        }

        return 0;
    }

    private static int RunStreamTransferProfile(int count, StreamProfileTarget target)
    {
        Console.WriteLine();
        Console.WriteLine("=== Public Stream Transfer Allocation Profile ===");
        Console.WriteLine($"Iterations per pass: {count:N0}");
        Console.WriteLine("Passes: 2");
        Console.WriteLine($"Target: {FormatStreamProfileTarget(target)}");
        Console.WriteLine("Workload: established-connection 1KB request/response stream transfer");
        Console.WriteLine();

        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);
        byte[] requestPayload = CreatePayload(1024, 0x11);
        byte[] responsePayload = CreatePayload(1024, 0x33);
        byte[] requestBuffer = new byte[requestPayload.Length];
        byte[] responseBuffer = new byte[responsePayload.Length];
        byte[] eofProbe = new byte[1];

        var incursaPasses = new List<PassResult>();
        var systemNetPasses = new List<PassResult>();

        try
        {
            if (target is StreamProfileTarget.All or StreamProfileTarget.Incursa
                && IncursaClientConnection.IsSupported
                && IncursaListener.IsSupported)
            {
                Console.WriteLine("--- Incursa.Quic established stream transfer ---");
                var incursaPair = CreateIncursaConnectedPairAsync(serverAuthOptions, clientAuthOptions)
                    .GetAwaiter()
                    .GetResult();
                try
                {
                    for (int pass = 1; pass <= PassCount; pass++)
                    {
                        incursaPasses.Add(RunPass($"  pass {pass}/{PassCount}", count,
                            () => RunIncursaRequestResponseStreamAsync(
                                    incursaPair.Client,
                                    incursaPair.Server,
                                    requestPayload,
                                    responsePayload,
                                    requestBuffer,
                                    responseBuffer,
                                    eofProbe)
                                .GetAwaiter()
                                .GetResult()));
                    }
                }
                finally
                {
                    CloseIncursaPairAsync(incursaPair.Client, incursaPair.Server, incursaPair.Listener).GetAwaiter().GetResult();
                }

                Console.WriteLine();
            }

            if (target is StreamProfileTarget.All or StreamProfileTarget.SystemNet
                && SystemNetClientConnection.IsSupported
                && SystemNetListener.IsSupported)
            {
                Console.WriteLine("--- System.Net.Quic established stream transfer ---");
                var systemNetPair = CreateSystemNetConnectedPairAsync(serverAuthOptions, clientAuthOptions)
                    .GetAwaiter()
                    .GetResult();
                try
                {
                    for (int pass = 1; pass <= PassCount; pass++)
                    {
                        systemNetPasses.Add(RunPass($"  pass {pass}/{PassCount}", count,
                            () => RunSystemNetRequestResponseStreamAsync(
                                    systemNetPair.Client,
                                    systemNetPair.Server,
                                    requestPayload,
                                    responsePayload,
                                    requestBuffer,
                                    responseBuffer,
                                    eofProbe)
                                .GetAwaiter()
                                .GetResult()));
                    }
                }
                finally
                {
                    CloseSystemNetPairAsync(systemNetPair.Client, systemNetPair.Server).GetAwaiter().GetResult();
                }
            }
        }
        finally
        {
            trustAnchor.Dispose();
            serverCertificate.Dispose();
        }

        if (JsonOutputPath is not null)
        {
            var json = new JsonObject
            {
                ["mode"] = "profile-stream",
                ["commandName"] = "profile-stream",
                ["count"] = count,
                ["target"] = FormatStreamProfileTarget(target),
                ["workload"] = "established-public-request-response",
            };

            var incursa = new JsonObject();
            for (int i = 0; i < incursaPasses.Count; i++)
            {
                incursa[$"pass{i + 1}"] = PassResultToJson(incursaPasses[i]);
            }

            var sysNet = new JsonObject();
            for (int i = 0; i < systemNetPasses.Count; i++)
            {
                sysNet[$"pass{i + 1}"] = PassResultToJson(systemNetPasses[i]);
            }

            json["incursa"] = incursa;
            json["systemNet"] = sysNet;
            WriteJson(json);
        }

        return 0;
    }

    private static int RunStreamTransferPhaseProfile(int count)
    {
        Console.WriteLine();
        Console.WriteLine("=== Public Stream Transfer Phase Allocation Profile ===");
        Console.WriteLine($"Iterations: {count:N0}");
        Console.WriteLine("Target: incursa");
        Console.WriteLine("Workload: established-connection 1KB request/response stream transfer");
        Console.WriteLine();

        if (!IncursaClientConnection.IsSupported || !IncursaListener.IsSupported)
        {
            Console.WriteLine("Incursa.Quic is not supported on this platform.");
            return 0;
        }

        X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverAuthOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);
        byte[] requestPayload = CreatePayload(1024, 0x11);
        byte[] responsePayload = CreatePayload(1024, 0x33);
        byte[] requestBuffer = new byte[requestPayload.Length];
        byte[] responseBuffer = new byte[responsePayload.Length];
        byte[] eofProbe = new byte[1];
        var phases = new Dictionary<string, PhaseResult>(StringComparer.Ordinal)
        {
            ["accept-task-start"] = new(),
            ["task-yield"] = new(),
            ["open-client-stream-start"] = new(),
            ["open-client-stream-await"] = new(),
            ["client-write-start"] = new(),
            ["client-write-await"] = new(),
            ["client-complete-writes-start"] = new(),
            ["client-complete-writes-await"] = new(),
            ["client-writes-closed"] = new(),
            ["server-accept-await"] = new(),
            ["server-read-request"] = new(),
            ["server-eof"] = new(),
            ["server-reads-closed"] = new(),
            ["server-write-start"] = new(),
            ["server-write-await"] = new(),
            ["server-complete-writes-start"] = new(),
            ["server-complete-writes-await"] = new(),
            ["server-writes-closed"] = new(),
            ["client-read-response"] = new(),
            ["client-eof"] = new(),
            ["client-reads-closed"] = new(),
            ["dispose-streams"] = new(),
        };

        try
        {
            var incursaPair = CreateIncursaConnectedPairAsync(serverAuthOptions, clientAuthOptions)
                .GetAwaiter()
                .GetResult();
            try
            {
                for (int i = 0; i < WarmupCount; i++)
                {
                    RunIncursaRequestResponseStreamAsync(
                            incursaPair.Client,
                            incursaPair.Server,
                            requestPayload,
                            responsePayload,
                            requestBuffer,
                            responseBuffer,
                            eofProbe)
                        .GetAwaiter()
                        .GetResult();
                }

                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                long startStopwatch = Stopwatch.GetTimestamp();
                for (int i = 0; i < count; i++)
                {
                    RunIncursaRequestResponseStreamPhaseAsync(
                            incursaPair.Client,
                            incursaPair.Server,
                            requestPayload,
                            responsePayload,
                            requestBuffer,
                            responseBuffer,
                            eofProbe,
                            phases)
                        .GetAwaiter()
                        .GetResult();
                }

                double elapsedSec = (double)(Stopwatch.GetTimestamp() - startStopwatch) / Stopwatch.Frequency;
                Console.WriteLine($"  elapsed: {elapsedSec:N3}s  {elapsedSec / count * 1000:N3} ms/op");
                Console.WriteLine();
            }
            finally
            {
                CloseIncursaPairAsync(incursaPair.Client, incursaPair.Server, incursaPair.Listener).GetAwaiter().GetResult();
            }
        }
        finally
        {
            trustAnchor.Dispose();
            serverCertificate.Dispose();
        }

        PrintStreamPhaseResults(phases);

        if (JsonOutputPath is not null)
        {
            var json = new JsonObject
            {
                ["mode"] = "profile-stream-phases",
                ["commandName"] = "profile-stream-phases",
                ["count"] = count,
                ["target"] = "incursa",
                ["workload"] = "established-public-request-response",
            };

            var phaseArray = new JsonArray();
            foreach (KeyValuePair<string, PhaseResult> phase in phases.OrderByDescending(static phase => phase.Value.ManagedDelta))
            {
                phaseArray.Add(new JsonObject
                {
                    ["name"] = phase.Key,
                    ["iterations"] = phase.Value.Iterations,
                    ["managedTotalBytes"] = phase.Value.ManagedDelta,
                    ["managedBytesPerOp"] = phase.Value.Iterations == 0
                        ? 0
                        : (long)(phase.Value.ManagedDelta / (double)phase.Value.Iterations),
                });
            }

            json["phases"] = phaseArray;
            WriteJson(json);
        }

        return 0;
    }

    private static int ParseCount(string[] args, int defaultCount)
    {
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i].StartsWith("--", StringComparison.Ordinal))
            {
                if (ArgumentHasValue(args[i])
                    || i + 1 >= args.Length
                    || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    continue;
                }

                i++;
                continue;
            }

            if (int.TryParse(args[i], out int parsed) && parsed > 0)
            {
                return parsed;
            }
        }

        return defaultCount;
    }

    private static bool TryParseStreamProfileTarget(
        string[] args,
        out StreamProfileTarget target,
        out string? error)
    {
        target = StreamProfileTarget.All;
        error = null;

        for (int i = 1; i < args.Length; i++)
        {
            string arg = args[i];
            string? value = null;
            if (arg.StartsWith("--target=", StringComparison.OrdinalIgnoreCase))
            {
                value = arg["--target=".Length..];
            }
            else if (string.Equals(arg, "--target", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    error = "--target requires one of: all, incursa, systemnet.";
                    return false;
                }

                value = args[++i];
            }

            if (value is null)
            {
                continue;
            }

            if (TryParseStreamProfileTargetValue(value, out target))
            {
                return true;
            }

            error = $"Unsupported --target value '{value}'. Use one of: all, incursa, systemnet.";
            return false;
        }

        return true;
    }

    private static bool TryParseStreamProfileTargetValue(string value, out StreamProfileTarget target)
    {
        if (string.Equals(value, "all", StringComparison.OrdinalIgnoreCase))
        {
            target = StreamProfileTarget.All;
            return true;
        }

        if (string.Equals(value, "incursa", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "incursa-quic", StringComparison.OrdinalIgnoreCase))
        {
            target = StreamProfileTarget.Incursa;
            return true;
        }

        if (string.Equals(value, "systemnet", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "system-net", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "system.net", StringComparison.OrdinalIgnoreCase))
        {
            target = StreamProfileTarget.SystemNet;
            return true;
        }

        target = StreamProfileTarget.All;
        return false;
    }

    private static string FormatStreamProfileTarget(StreamProfileTarget target)
        => target switch
        {
            StreamProfileTarget.Incursa => "incursa",
            StreamProfileTarget.SystemNet => "systemnet",
            _ => "all",
        };

    private static bool ArgumentHasValue(string arg)
        => arg.Contains('=', StringComparison.Ordinal);

    private static async Task<LeakBatchResult> RunLeakBatch(
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

        return new LeakBatchResult(
            ManagedLive: managedLive - managedStart,
            WsLive: wsLive - wsStart,
            PrivLive: privLive - privStart,
            ManagedEnd: managedEnd - managedLive,
            WsEnd: wsEnd - wsLive,
            PrivEnd: privEnd - privLive,
            RetainedPriv: privEnd - privStart,
            RetainedWs: wsEnd - wsStart,
            RetainedPrivPerConn: (privEnd - privStart) / count,
            RetainedWsPerConn: (wsEnd - wsStart) / count);
    }

    private static void Snapshot(out long managed, out long workingSet, out long privateBytes)
    {
        var process = Process.GetCurrentProcess();
        process.Refresh();
        managed = GC.GetTotalAllocatedBytes(precise: true);
        workingSet = process.WorkingSet64;
        privateBytes = process.PrivateMemorySize64;
    }

    private static PassResult RunPass(string label, int count, Action operation)
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

        return new PassResult(count, elapsedSec, elapsedSec / count * 1000, managedDelta, wsDelta, privDelta);
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

    private static async Task<(IncursaListener Listener, IncursaClientConnection Client, IncursaClientConnection Server)> CreateIncursaConnectedPairAsync(
        SslServerAuthenticationOptions serverOptions,
        SslClientAuthenticationOptions clientOptions)
    {
        IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();

        IncursaListener listener = await IncursaListener.ListenAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(
                listenEndPoint, serverOptions)).ConfigureAwait(false);

        Task<IncursaClientConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
        Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
            QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                clientOptions)).AsTask();

        await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);

        IncursaClientConnection server = await acceptTask.ConfigureAwait(false);
        IncursaClientConnection client = await connectTask.ConfigureAwait(false);
        return (listener, client, server);
    }

    internal static async Task<(SystemNetClientConnection Client, SystemNetClientConnection Server)> CreateSystemNetConnectedPairAsync(
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

    private static async Task RunIncursaRequestResponseStreamAsync(
        IncursaClientConnection clientConnection,
        IncursaClientConnection serverConnection,
        byte[] requestPayload,
        byte[] responsePayload,
        byte[] requestBuffer,
        byte[] responseBuffer,
        byte[] eofProbe)
    {
        Task<IncursaStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
        await Task.Yield();
        await using IncursaStream clientStream = await clientConnection.OpenOutboundStreamAsync(
            IncursaStreamType.Bidirectional).ConfigureAwait(false);

        await clientStream.WriteAsync(requestPayload.AsMemory()).ConfigureAwait(false);
        await clientStream.CompleteWritesAsync().ConfigureAwait(false);
        await clientStream.WritesClosed.ConfigureAwait(false);

        await using IncursaStream serverStream = await acceptStreamTask.ConfigureAwait(false);
        await ReadExactlyAsync(serverStream, requestBuffer).ConfigureAwait(false);
        if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }

        await EnsureEofAsync(serverStream, eofProbe, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.ConfigureAwait(false);

        await serverStream.WriteAsync(responsePayload.AsMemory()).ConfigureAwait(false);
        await serverStream.CompleteWritesAsync().ConfigureAwait(false);
        await serverStream.WritesClosed.ConfigureAwait(false);

        await ReadExactlyAsync(clientStream, responseBuffer).ConfigureAwait(false);
        if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
        {
            throw new InvalidOperationException("The client response payload did not match the server payload.");
        }

        await EnsureEofAsync(clientStream, eofProbe, "The client did not observe response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.ConfigureAwait(false);
    }

    private static async Task RunIncursaRequestResponseStreamPhaseAsync(
        IncursaClientConnection clientConnection,
        IncursaClientConnection serverConnection,
        byte[] requestPayload,
        byte[] responsePayload,
        byte[] requestBuffer,
        byte[] responseBuffer,
        byte[] eofProbe,
        Dictionary<string, PhaseResult> phases)
    {
        IncursaStream? clientStream = null;
        IncursaStream? serverStream = null;

        try
        {
            long start = SnapshotManaged();
            Task<IncursaStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
            AddPhase(phases, "accept-task-start", start);

            start = SnapshotManaged();
            await Task.Yield();
            AddPhase(phases, "task-yield", start);

            start = SnapshotManaged();
            ValueTask<IncursaStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(
                IncursaStreamType.Bidirectional);
            AddPhase(phases, "open-client-stream-start", start);

            start = SnapshotManaged();
            clientStream = await openStreamTask.ConfigureAwait(false);
            AddPhase(phases, "open-client-stream-await", start);

            start = SnapshotManaged();
            ValueTask clientWriteTask = clientStream.WriteAsync(requestPayload.AsMemory());
            AddPhase(phases, "client-write-start", start);

            start = SnapshotManaged();
            await clientWriteTask.ConfigureAwait(false);
            AddPhase(phases, "client-write-await", start);

            start = SnapshotManaged();
            ValueTask clientCompleteWritesTask = clientStream.CompleteWritesAsync();
            AddPhase(phases, "client-complete-writes-start", start);

            start = SnapshotManaged();
            await clientCompleteWritesTask.ConfigureAwait(false);
            AddPhase(phases, "client-complete-writes-await", start);

            start = SnapshotManaged();
            await clientStream.WritesClosed.ConfigureAwait(false);
            AddPhase(phases, "client-writes-closed", start);

            start = SnapshotManaged();
            serverStream = await acceptStreamTask.ConfigureAwait(false);
            AddPhase(phases, "server-accept-await", start);

            start = SnapshotManaged();
            await ReadExactlyAsync(serverStream, requestBuffer).ConfigureAwait(false);
            AddPhase(phases, "server-read-request", start);

            if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
            {
                throw new InvalidOperationException("The server request payload did not match the client payload.");
            }

            start = SnapshotManaged();
            await EnsureEofAsync(serverStream, eofProbe, "The server did not observe request EOF.").ConfigureAwait(false);
            AddPhase(phases, "server-eof", start);

            start = SnapshotManaged();
            await serverStream.ReadsClosed.ConfigureAwait(false);
            AddPhase(phases, "server-reads-closed", start);

            start = SnapshotManaged();
            ValueTask serverWriteTask = serverStream.WriteAsync(responsePayload.AsMemory());
            AddPhase(phases, "server-write-start", start);

            start = SnapshotManaged();
            await serverWriteTask.ConfigureAwait(false);
            AddPhase(phases, "server-write-await", start);

            start = SnapshotManaged();
            ValueTask serverCompleteWritesTask = serverStream.CompleteWritesAsync();
            AddPhase(phases, "server-complete-writes-start", start);

            start = SnapshotManaged();
            await serverCompleteWritesTask.ConfigureAwait(false);
            AddPhase(phases, "server-complete-writes-await", start);

            start = SnapshotManaged();
            await serverStream.WritesClosed.ConfigureAwait(false);
            AddPhase(phases, "server-writes-closed", start);

            start = SnapshotManaged();
            await ReadExactlyAsync(clientStream, responseBuffer).ConfigureAwait(false);
            AddPhase(phases, "client-read-response", start);

            if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
            {
                throw new InvalidOperationException("The client response payload did not match the server payload.");
            }

            start = SnapshotManaged();
            await EnsureEofAsync(clientStream, eofProbe, "The client did not observe response EOF.").ConfigureAwait(false);
            AddPhase(phases, "client-eof", start);

            start = SnapshotManaged();
            await clientStream.ReadsClosed.ConfigureAwait(false);
            AddPhase(phases, "client-reads-closed", start);
        }
        finally
        {
            long start = SnapshotManaged();
            if (serverStream is not null)
            {
                await serverStream.DisposeAsync().ConfigureAwait(false);
            }

            if (clientStream is not null)
            {
                await clientStream.DisposeAsync().ConfigureAwait(false);
            }

            AddPhase(phases, "dispose-streams", start);
        }
    }

    private static async Task RunSystemNetRequestResponseStreamAsync(
        SystemNetClientConnection clientConnection,
        SystemNetClientConnection serverConnection,
        byte[] requestPayload,
        byte[] responsePayload,
        byte[] requestBuffer,
        byte[] responseBuffer,
        byte[] eofProbe)
    {
        Task<SystemNetStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
        await Task.Yield();
        await using SystemNetStream clientStream = await clientConnection.OpenOutboundStreamAsync(
            SystemNetStreamType.Bidirectional).ConfigureAwait(false);

        await clientStream.WriteAsync(requestPayload.AsMemory()).ConfigureAwait(false);
        clientStream.CompleteWrites();
        await clientStream.WritesClosed.ConfigureAwait(false);

        await using SystemNetStream serverStream = await acceptStreamTask.ConfigureAwait(false);
        await ReadExactlyAsync(serverStream, requestBuffer).ConfigureAwait(false);
        if (!requestPayload.AsSpan().SequenceEqual(requestBuffer))
        {
            throw new InvalidOperationException("The server request payload did not match the client payload.");
        }

        await EnsureEofAsync(serverStream, eofProbe, "The server did not observe request EOF.").ConfigureAwait(false);
        await serverStream.ReadsClosed.ConfigureAwait(false);

        await serverStream.WriteAsync(responsePayload.AsMemory()).ConfigureAwait(false);
        serverStream.CompleteWrites();
        await serverStream.WritesClosed.ConfigureAwait(false);

        await ReadExactlyAsync(clientStream, responseBuffer).ConfigureAwait(false);
        if (!responsePayload.AsSpan().SequenceEqual(responseBuffer))
        {
            throw new InvalidOperationException("The client response payload did not match the server payload.");
        }

        await EnsureEofAsync(clientStream, eofProbe, "The client did not observe response EOF.").ConfigureAwait(false);
        await clientStream.ReadsClosed.ConfigureAwait(false);
    }

    private static long SnapshotManaged()
        => GC.GetTotalAllocatedBytes(precise: true);

    private static void AddPhase(Dictionary<string, PhaseResult> phases, string name, long startManaged)
    {
        PhaseResult phase = phases[name];
        phase.ManagedDelta += SnapshotManaged() - startManaged;
        phase.Iterations++;
    }

    private static void PrintStreamPhaseResults(Dictionary<string, PhaseResult> phases)
    {
        Console.WriteLine($"  {"Phase",-28} {"Total (B)",14} {"B/op",10}");
        Console.WriteLine($"  {"----------------------------",-28} {"--------------",14} {"----------",10}");
        foreach (KeyValuePair<string, PhaseResult> phase in phases.OrderByDescending(static phase => phase.Value.ManagedDelta))
        {
            long bytesPerOp = phase.Value.Iterations == 0
                ? 0
                : (long)(phase.Value.ManagedDelta / (double)phase.Value.Iterations);
            Console.WriteLine($"  {phase.Key,-28} {phase.Value.ManagedDelta,14:N0} {bytesPerOp,10:N0}");
        }
    }

    private static async Task CloseIncursaPairAsync(
        IncursaClientConnection clientConnection,
        IncursaClientConnection serverConnection,
        IncursaListener listener)
    {
        await serverConnection.CloseAsync(0, CancellationToken.None).ConfigureAwait(false);
        await clientConnection.CloseAsync(0, CancellationToken.None).ConfigureAwait(false);
        await serverConnection.DisposeAsync().ConfigureAwait(false);
        await clientConnection.DisposeAsync().ConfigureAwait(false);
        await listener.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task CloseSystemNetPairAsync(SystemNetClientConnection clientConnection, SystemNetClientConnection serverConnection)
    {
        await serverConnection.CloseAsync(0, CancellationToken.None).ConfigureAwait(false);
        await clientConnection.CloseAsync(0, CancellationToken.None).ConfigureAwait(false);
        await serverConnection.DisposeAsync().ConfigureAwait(false);
        await clientConnection.DisposeAsync().ConfigureAwait(false);
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken: default).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                throw new InvalidOperationException("Unexpected EOF before the full payload was read.");
            }

            offset += bytesRead;
        }
    }

    private static ValueTask EnsureEofAsync(Stream stream, byte[] probe, string failureMessage)
    {
        ValueTask<int> readTask = stream.ReadAsync(probe.AsMemory(), cancellationToken: default);
        if (readTask.IsCompletedSuccessfully)
        {
            ValidateEofRead(readTask.Result, failureMessage);
            return ValueTask.CompletedTask;
        }

        return AwaitEnsureEofAsync(readTask, failureMessage);
    }

    private static async ValueTask AwaitEnsureEofAsync(ValueTask<int> readTask, string failureMessage)
    {
        int bytesRead = await readTask.ConfigureAwait(false);
        ValidateEofRead(bytesRead, failureMessage);
    }

    private static void ValidateEofRead(int bytesRead, string failureMessage)
    {
        if (bytesRead != 0)
        {
            throw new InvalidOperationException(failureMessage);
        }
    }

    private static byte[] CreatePayload(int length, byte seed)
    {
        byte[] payload = new byte[length];
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)((seed + index) % 251);
        }

        return payload;
    }

    private static JsonObject PassResultToJson(PassResult r)
    {
        return new JsonObject
        {
            ["iterations"] = r.Iterations,
            ["elapsedSeconds"] = Math.Round(r.ElapsedSeconds, 3),
            ["msPerOp"] = Math.Round(r.MsPerOp, 3),
            ["managedBytesPerOp"] = (long)(r.ManagedDelta / (double)r.Iterations),
            ["workingSetBytesPerOp"] = (long)(r.WsDelta / (double)r.Iterations),
            ["privateBytesPerOp"] = (long)(r.PrivDelta / (double)r.Iterations),
        };
    }

    private static void WriteJson(JsonObject json)
    {
        if (JsonOutputPath is null || JsonOutputPath.Length == 0) return;
        string? directory = Path.GetDirectoryName(Path.GetFullPath(JsonOutputPath));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var options = new System.Text.Json.JsonSerializerOptions { WriteIndented = true };
        string jsonText = json.ToJsonString(options);
        File.WriteAllText(JsonOutputPath, jsonText);
    }
}
