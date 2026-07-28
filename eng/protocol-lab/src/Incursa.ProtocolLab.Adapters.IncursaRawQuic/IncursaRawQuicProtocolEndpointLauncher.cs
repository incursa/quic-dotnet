// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Incursa.ProtocolLab.Adapter.Contracts;

namespace Incursa.ProtocolLab.Adapters.IncursaRawQuic;

internal static class IncursaRawQuicProtocolEndpointLauncher
{
    public static async Task<IncursaRawQuicEndpointProcess> StartAsync(string repositoryRoot, IncursaRawQuicSession session, IncursaRawQuicEndpointPlan plan, string projectPath, CancellationToken ct)
    {
        var resolvedProject = Path.IsPathFullyQualified(projectPath) ? projectPath : Path.GetFullPath(Path.Combine(repositoryRoot, projectPath));
        var projectDirectory = Path.GetDirectoryName(resolvedProject) ?? repositoryRoot;
        var assemblyName = Path.GetFileNameWithoutExtension(resolvedProject);
        var port = plan.Port > 0 ? plan.Port : GetFreePort();

        var si = new ProcessStartInfo
        {
            WorkingDirectory = repositoryRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        var incursaQuicSourceRoot = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT");
        if (!string.IsNullOrWhiteSpace(incursaQuicSourceRoot))
        {
            var sourceProject = Path.GetFullPath(Path.Combine(
                incursaQuicSourceRoot,
                "eng",
                "protocol-lab",
                "servers",
                "IncursaRawQuicServer",
                "IncursaRawQuicServer.csproj"));
            if (!File.Exists(sourceProject))
            {
                throw new FileNotFoundException(
                    "The source-backed Incursa raw QUIC server project was not found.",
                    sourceProject);
            }

            var sourceProjectDirectory = Path.GetDirectoryName(sourceProject) ?? incursaQuicSourceRoot;
            var sourceAssemblyName = Path.GetFileNameWithoutExtension(sourceProject);
            if (ResolveBuiltServerExecutable(sourceProjectDirectory, sourceAssemblyName) is { } sourceExecutable)
            {
                EnsureExecutablePermission(sourceExecutable);
                si.FileName = sourceExecutable;
                si.ArgumentList.Add(port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            else if (ResolveBuiltServerDll(sourceProjectDirectory, sourceAssemblyName) is { } sourceDll)
            {
                si.FileName = "dotnet";
                si.ArgumentList.Add("exec");
                si.ArgumentList.Add(sourceDll);
                si.ArgumentList.Add(port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            else
            {
                si.FileName = "dotnet";
                si.ArgumentList.Add("run");
                si.ArgumentList.Add("--configuration");
                si.ArgumentList.Add("Release");
                si.ArgumentList.Add("--no-launch-profile");
                si.ArgumentList.Add("--project");
                si.ArgumentList.Add(sourceProject);
                si.ArgumentList.Add($"-p:IncursaQuicSourceRoot={incursaQuicSourceRoot}");
                si.ArgumentList.Add("--");
                si.ArgumentList.Add(port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            si.Environment["PROTOCOL_LAB_INCURSA_QUIC_SOURCE_ROOT"] = incursaQuicSourceRoot;
        }
        else if (ResolveBuiltServerExecutable(projectDirectory, assemblyName) is { } directExec)
        {
            EnsureExecutablePermission(directExec);
            si.FileName = directExec;
            si.ArgumentList.Add(port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        else if (ResolveBuiltServerDll(projectDirectory, assemblyName) is { } directExecDll)
        {
            // Prefer the built Release/Debug output so startup does not pay the dotnet-run build cost.
            si.FileName = "dotnet";
            si.ArgumentList.Add("exec");
            si.ArgumentList.Add(directExecDll);
            si.ArgumentList.Add(port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        else
        {
            si.FileName = "dotnet";
            si.ArgumentList.Add("run");
            si.ArgumentList.Add("--configuration");
            si.ArgumentList.Add("Release");
            si.ArgumentList.Add("--no-restore");
            si.ArgumentList.Add("--no-launch-profile");
            si.ArgumentList.Add("--project");
            si.ArgumentList.Add(resolvedProject);
            si.ArgumentList.Add("--");
            si.ArgumentList.Add(port.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_ALPN"] = plan.Alpn;
        si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_CERT_SUBJECT"] = plan.CertificateSubject;
        var payloadDirection = plan.Scenario.QuicTransport?.PayloadDirection;
        if (!string.IsNullOrWhiteSpace(payloadDirection))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_PAYLOAD_DIRECTION"] = payloadDirection;
        }
        if (plan.Scenario.QuicTransport?.PayloadSizeBytes is > 0 and var payloadSizeBytes)
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_PAYLOAD_SIZE_BYTES"] = payloadSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var behavior = plan.Scenario.QuicTransport?.Behavior;
        if (!string.IsNullOrWhiteSpace(behavior))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_BEHAVIOR"] = behavior;
        }

        var debugLogging = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_DEBUG");
        if (!string.IsNullOrWhiteSpace(debugLogging))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_DEBUG"] = debugLogging;
        }

        var summaryLogging = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_SUMMARY");
        if (!string.IsNullOrWhiteSpace(summaryLogging))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_SUMMARY"] = summaryLogging;
        }

        var capacitySummaryLogging = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_CAPACITY_SUMMARY");
        if (!string.IsNullOrWhiteSpace(capacitySummaryLogging))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_CAPACITY_SUMMARY"] = capacitySummaryLogging;
        }

        var receiveCreditPolicy = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY");
        if (!string.IsNullOrWhiteSpace(receiveCreditPolicy))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY"] = receiveCreditPolicy;
        }

        var applicationSendTurnPolicy = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_TURN_POLICY");
        if (!string.IsNullOrWhiteSpace(applicationSendTurnPolicy))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_TURN_POLICY"] = applicationSendTurnPolicy;
        }

        var oversizedWriteAdmissionPolicy = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_OVERSIZED_WRITE_ADMISSION_POLICY");
        if (!string.IsNullOrWhiteSpace(oversizedWriteAdmissionPolicy))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_OVERSIZED_WRITE_ADMISSION_POLICY"] = oversizedWriteAdmissionPolicy;
        }

        var applicationSendBatchPolicy = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_BATCH_POLICY");
        if (!string.IsNullOrWhiteSpace(applicationSendBatchPolicy))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_BATCH_POLICY"] = applicationSendBatchPolicy;
        }

        var bufferCopyPolicy = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_BUFFER_COPY_POLICY");
        if (!string.IsNullOrWhiteSpace(bufferCopyPolicy))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_BUFFER_COPY_POLICY"] = bufferCopyPolicy;
        }

        var admissionPerformanceCampaignId = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CAMPAIGN_ID");
        if (!string.IsNullOrWhiteSpace(admissionPerformanceCampaignId))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CAMPAIGN_ID"] = admissionPerformanceCampaignId;
        }

        var admissionPerformanceManifestContentSha256 = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_MANIFEST_CONTENT_SHA256");
        if (!string.IsNullOrWhiteSpace(admissionPerformanceManifestContentSha256))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_MANIFEST_CONTENT_SHA256"] = admissionPerformanceManifestContentSha256;
        }

        var admissionPerformanceCellId = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CELL_ID");
        if (!string.IsNullOrWhiteSpace(admissionPerformanceCellId))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CELL_ID"] = admissionPerformanceCellId;
        }

        var admissionPerformanceCellContentSha256 = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CELL_CONTENT_SHA256");
        if (!string.IsNullOrWhiteSpace(admissionPerformanceCellContentSha256))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_CELL_CONTENT_SHA256"] = admissionPerformanceCellContentSha256;
        }

        var admissionPerformanceOversizedWriteAdmissionPolicy = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_OVERSIZED_WRITE_ADMISSION_POLICY");
        if (!string.IsNullOrWhiteSpace(admissionPerformanceOversizedWriteAdmissionPolicy))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_OVERSIZED_WRITE_ADMISSION_POLICY"] = admissionPerformanceOversizedWriteAdmissionPolicy;
        }

        var admissionPerformanceApplicationSendBatchPolicy = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_APPLICATION_SEND_BATCH_POLICY");
        if (!string.IsNullOrWhiteSpace(admissionPerformanceApplicationSendBatchPolicy))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_APPLICATION_SEND_BATCH_POLICY"] = admissionPerformanceApplicationSendBatchPolicy;
        }

        var admissionPerformanceBufferCopyPolicy = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_BUFFER_COPY_POLICY");
        if (!string.IsNullOrWhiteSpace(admissionPerformanceBufferCopyPolicy))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_ADMISSION_PERFORMANCE_BUFFER_COPY_POLICY"] = admissionPerformanceBufferCopyPolicy;
        }

        var qlogPath = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_QLOG_PATH");
        if (!string.IsNullOrWhiteSpace(qlogPath))
        {
            si.Environment["PROTOCOL_LAB_INCURSA_RAW_QUIC_QLOG_PATH"] = qlogPath;
        }

        var bindAddress = Environment.GetEnvironmentVariable("PROTOCOL_LAB_TARGET_BIND_ADDRESS");
        if (!string.IsNullOrWhiteSpace(bindAddress))
        {
            si.Environment["PROTOCOL_LAB_TARGET_BIND_ADDRESS"] = bindAddress;
        }

        var advertisedHost = Environment.GetEnvironmentVariable("PROTOCOL_LAB_TARGET_ADVERTISE_HOST");
        if (!string.IsNullOrWhiteSpace(advertisedHost))
        {
            si.Environment["PROTOCOL_LAB_TARGET_ADVERTISE_HOST"] = advertisedHost;
        }

        var cl = BuildCommandLine(si.FileName, [.. si.ArgumentList]);
        await File.WriteAllTextAsync(session.CommandLinePath, cl, ct);

        var process = Process.Start(si) ?? throw new InvalidOperationException("Failed to start Incursa raw QUIC server.");
        var stdoutTask = CopyToFileAsync(process.StandardOutput, session.StdoutPath, ct);
        var stderrTask = CopyToFileAsync(process.StandardError, session.StderrPath, ct);

        advertisedHost = ResolveAdvertisedHost(advertisedHost, bindAddress);
        var endpointIsLoopback = IsLoopbackHost(advertisedHost);

        return new IncursaRawQuicEndpointProcess(process, stdoutTask, stderrTask, new AdapterEndpoint
        {
            EndpointId = "endpoint-quic-001", Purpose = "server", Scheme = "quic", Protocol = "quic",
            Host = advertisedHost, Port = port, Authority = $"{advertisedHost}:{port}", SocketAddress = $"{advertisedHost}:{port}",
            NetworkMode = endpointIsLoopback ? "process-local" : "lab-routed", BindMode = endpointIsLoopback ? "loopback" : "lab-address",
            Tls = new AdapterTlsNotes { CertificateMode = "incursa-raw-quic-self-signed", CertificateNotes = $"Incursa raw QUIC server self-signed certificate subject '{plan.CertificateSubject}'.", Sni = "localhost", VerificationNotes = "Loopback certificate validation bypassed." },
            Extensions = new Dictionary<string, JsonElement> { ["alpn"] = ProtocolLabAdapterJson.SerializeValue(new[] { plan.Alpn }), ["sni"] = ProtocolLabAdapterJson.SerializeValue("localhost"), ["transport"] = ProtocolLabAdapterJson.SerializeValue("udp"), ["streamBehavior"] = ProtocolLabAdapterJson.SerializeValue("bidirectional"), ["supportedStreamDirections"] = ProtocolLabAdapterJson.SerializeValue(new[] { "bidirectional" }), ["datagramSupported"] = ProtocolLabAdapterJson.SerializeValue(false), ["zeroRttSupported"] = ProtocolLabAdapterJson.SerializeValue(false) }
        }, cl, session.StdoutPath, session.StderrPath, port);
    }

    private static string ResolveAdvertisedHost(string? advertisedHost, string? bindAddress)
    {
        if (!string.IsNullOrWhiteSpace(advertisedHost))
        {
            return advertisedHost;
        }

        if (!string.IsNullOrWhiteSpace(bindAddress) &&
            IPAddress.TryParse(bindAddress, out var parsedBindAddress) &&
            !IPAddress.IsLoopback(parsedBindAddress) &&
            !parsedBindAddress.Equals(IPAddress.Any) &&
            !parsedBindAddress.Equals(IPAddress.IPv6Any))
        {
            return parsedBindAddress.ToString();
        }

        return "127.0.0.1";
    }

    private static bool IsLoopbackHost(string host)
    {
        return IPAddress.TryParse(host, out var address)
            ? IPAddress.IsLoopback(address)
            : string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase);
    }

    private static string? ResolveBuiltServerExecutable(string projectDirectory, string assemblyName)
    {
        var names = OperatingSystem.IsWindows()
            ? new[] { assemblyName + ".exe", assemblyName }
            : new[] { assemblyName, assemblyName + ".exe" };

        return ResolveNewestBuildOutput(projectDirectory, names, packageOnly: true);
    }

    private static string? ResolveBuiltServerDll(string projectDirectory, string assemblyName)
    {
        return ResolveNewestBuildOutput(projectDirectory, [assemblyName + ".dll"], packageOnly: false);
    }

    private static string? ResolveNewestBuildOutput(string projectDirectory, IReadOnlyCollection<string> fileNames, bool packageOnly)
    {
        var candidateRoots = new[] { Path.Combine(projectDirectory, "bin", "Release"), Path.Combine(projectDirectory, "bin", "Debug") };
        return candidateRoots
            .Where(Directory.Exists)
            .SelectMany(candidateRoot => packageOnly
                ? EnumeratePackageBuildOutputs(candidateRoot, fileNames)
                : EnumerateFrameworkBuildOutputs(candidateRoot, fileNames))
            .Where(path => fileNames.Contains(Path.GetFileName(path), StringComparer.OrdinalIgnoreCase))
            .Select(path => new FileInfo(path))
            .OrderByDescending(info => info.LastWriteTimeUtc)
            .Select(info => info.FullName)
            .FirstOrDefault();
    }

    private static IEnumerable<string> EnumeratePackageBuildOutputs(string candidateRoot, IReadOnlyCollection<string> fileNames)
    {
        var packageRoot = Path.Combine(candidateRoot, "protocol-lab-package");
        if (!Directory.Exists(packageRoot))
        {
            yield break;
        }

        foreach (var fileName in fileNames)
        {
            var candidate = Path.Combine(packageRoot, fileName);
            if (File.Exists(candidate))
            {
                yield return candidate;
            }
        }
    }

    private static IEnumerable<string> EnumerateFrameworkBuildOutputs(string candidateRoot, IReadOnlyCollection<string> fileNames)
    {
        foreach (var fileName in fileNames)
        {
            var directCandidate = Path.Combine(candidateRoot, fileName);
            if (File.Exists(directCandidate))
            {
                yield return directCandidate;
            }
        }

        foreach (var tfmDirectory in Directory.EnumerateDirectories(candidateRoot, "net*"))
        {
            foreach (var fileName in fileNames)
            {
                var candidate = Path.Combine(tfmDirectory, fileName);
                if (File.Exists(candidate))
                {
                    yield return candidate;
                }
            }
        }
    }

    private static void EnsureExecutablePermission(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            var mode = File.GetUnixFileMode(path);
            var executableMode = mode |
                UnixFileMode.UserExecute |
                UnixFileMode.GroupExecute |
                UnixFileMode.OtherExecute;
            if (executableMode != mode)
            {
                File.SetUnixFileMode(path, executableMode);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new InvalidOperationException($"Packaged raw QUIC server executable is not runnable: {path}", ex);
        }
    }

    private static async Task CopyToFileAsync(TextReader r, string path, CancellationToken ct) { await using var s = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read); await using var w = new StreamWriter(s, Encoding.UTF8); while (!ct.IsCancellationRequested) { var line = await r.ReadLineAsync(); if (line is null) break; await w.WriteLineAsync(line); await w.FlushAsync(); } }
    private static string BuildCommandLine(string exe, string[] args) => string.Join(" ", new[] { exe }.Concat(args).Select(a => a.Contains(' ') ? "\"" + a.Replace("\"", "\\\"") + "\"" : a));
    private static int GetFreePort() { using var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp); socket.Bind(new IPEndPoint(IPAddress.Loopback, 0)); return ((IPEndPoint)socket.LocalEndPoint!).Port; }
}

internal sealed class IncursaRawQuicEndpointProcess : IAsyncDisposable
{
    private readonly Process process; private readonly Task stdoutTask; private readonly Task stderrTask; private bool ready;

    public IncursaRawQuicEndpointProcess(Process process, Task stdoutTask, Task stderrTask, AdapterEndpoint endpoint, string commandLine, string stdoutPath, string stderrPath, int quicPort)
    {
        this.process = process; this.stdoutTask = stdoutTask; this.stderrTask = stderrTask; Endpoint = endpoint; CommandLine = commandLine; StdoutPath = stdoutPath; StderrPath = stderrPath; QuicPort = quicPort;
        _ = MonitorStdoutAsync();
    }

    public AdapterEndpoint Endpoint { get; } public string CommandLine { get; } public string StdoutPath { get; } public string StderrPath { get; } public int QuicPort { get; }
    public int ProcessId => process.Id;
    public bool HasExited { get { try { return process.HasExited; } catch { return true; } } }
    public int? ExitCode => HasExited ? process.ExitCode : null;
    public bool IsReady => ready;
    public long? WorkingSetBytes { get { try { process.Refresh(); return process.WorkingSet64; } catch { return null; } } }
    public double? CpuSeconds { get { try { process.Refresh(); return process.TotalProcessorTime.TotalSeconds; } catch { return null; } } }
    public void Refresh() { try { process.Refresh(); } catch { } }

    private async Task MonitorStdoutAsync()
    {
        try
        {
            using var reader = new StreamReader(new FileStream(StdoutPath, FileMode.OpenOrCreate, FileAccess.Read, FileShare.ReadWrite));
            while (!process.HasExited)
            {
                var line = await reader.ReadLineAsync();
                if (line is not null && line.StartsWith("QUIC_PORT=", StringComparison.OrdinalIgnoreCase))
                {
                    ready = true;
                    break;
                }
                if (line is null) await Task.Delay(100);
            }
        }
        catch { }
    }

    public async Task StopAsync()
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } catch { }
        try { await Task.WhenAll(stdoutTask, stderrTask); } catch { }
        process.Dispose();
    }

    public async ValueTask DisposeAsync() => await StopAsync();
}
