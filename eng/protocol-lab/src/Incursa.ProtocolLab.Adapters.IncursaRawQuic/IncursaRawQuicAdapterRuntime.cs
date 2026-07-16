// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Incursa.ProtocolLab.Adapter.Contracts;
using Incursa.ProtocolLab.Model;
using Microsoft.AspNetCore.Http;

namespace Incursa.ProtocolLab.Adapters.IncursaRawQuic;

public sealed record IncursaRawQuicAdapterOptions
{
    public string RepositoryRoot { get; init; } = Directory.GetCurrentDirectory();
    public string ControlPlaneBaseUrl { get; init; } = "";
    public string AdapterIdentityId { get; init; } = "incursa-raw-quic-adapter-v1";
    public string AdapterIdentityName { get; init; } = "Incursa Raw QUIC Adapter v1";
    public string AdapterIdentityVersion { get; init; } = "1.0.0";
    public string ImplementationId { get; init; } = "incursa-raw-quic";
    public string ImplementationName { get; init; } = "Incursa Raw QUIC";
    public string ImplementationVersion { get; init; } = "1.0.0";
    public string ImplementationImage { get; init; } = "";
    public string ContractVersion { get; init; } = "v1";
    public string SupportedScenarioSelectorExpression { get; init; } = "quic.transport.handshake-cold|quic.transport.latency.echo-1kb|quic.transport.connection-churn|quic.transport.stream-churn|quic.transport.stream-throughput.1mb|quic.transport.multiplex.100x64kb|quic.transport.stream-limits.100x64kb|quic.transport.flow-control.slow-reader-16x64kb|quic.transport.duplex-streams|quic.transport.duplex-streams-peer-matrix";
    public int QuicPort { get; init; }
    public string QuicAlpn { get; init; } = "plab-raw-quic";
    public string CertificateSubject { get; init; } = "CN=Incursa-RawQuic-Local";
    public string BenchmarkServerProjectPath { get; init; } = Path.Combine("servers", "IncursaRawQuicServer", "IncursaRawQuicServer.csproj");
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan ReadinessTimeout { get; init; } = TimeSpan.FromSeconds(15);
    public TimeSpan HttpTimeout { get; init; } = TimeSpan.FromSeconds(5);
    public string DefaultControlPlaneContentType { get; init; } = "application/json";
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
}

public sealed class IncursaRawQuicAdapterRuntime
{
    private readonly IncursaRawQuicAdapterOptions options;
    private readonly ConcurrentDictionary<string, IncursaRawQuicSession> sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> deletedSessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly object gate = new();
    private int sessionCounter;

    public IncursaRawQuicAdapterRuntime(IncursaRawQuicAdapterOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public Task<AdapterHealthResponse> GetHealthAsync() => Task.FromResult(new AdapterHealthResponse
    {
        AdapterIdentity = CreateAdapterIdentity(),
        Status = AdapterHealthStatus.Ready,
        VersionCompatibility = CreateCompatibility(),
        Message = "Incursa raw QUIC adapter ready.",
        ObservedAt = Now(),
        Capabilities = CreateCapabilities()
    });

    public Task<AdapterManifestResponse> GetManifestAsync() => Task.FromResult(new AdapterManifestResponse
    {
        AdapterIdentity = CreateAdapterIdentity(),
        ImplementationIdentity = CreateImplementationIdentity(),
        VersionCompatibility = CreateCompatibility(),
        SupportedRoles = ["server"],
        ClaimedCapabilities = CreateCapabilities(),
        SupportedScenarioSelectors = [new AdapterScenarioSelector { SelectorType = "scenario-id", Expression = options.SupportedScenarioSelectorExpression, Description = "Raw QUIC transport scenarios supported by the Incursa raw QUIC server." }],
        SupportedEndpointTypes = [new AdapterEndpointType { Type = "quic", Description = "Raw QUIC/UDP endpoint using Incursa raw QUIC server.", Protocols = ["quic"], Extensions = new Dictionary<string, JsonElement> { ["transport"] = ProtocolLabAdapterJson.SerializeValue("udp"), ["alpn"] = ProtocolLabAdapterJson.SerializeValue(options.QuicAlpn), ["streamModel"] = ProtocolLabAdapterJson.SerializeValue("quic-stream"), ["supportedStreamDirections"] = ProtocolLabAdapterJson.SerializeValue(new[] { "bidirectional" }), ["datagramSupported"] = ProtocolLabAdapterJson.SerializeValue(false), ["zeroRttSupported"] = ProtocolLabAdapterJson.SerializeValue(false) } }],
        SupportedArtifactTypes = [new AdapterArtifactType { Type = "stdout", Description = "Incursa raw QUIC server stdout capture.", ProducedByStates = ["starting", "running", "stopping", "stopped"] }, new AdapterArtifactType { Type = "stderr", Description = "Incursa raw QUIC server stderr capture.", ProducedByStates = ["starting", "running", "stopping", "stopped"] }, new AdapterArtifactType { Type = "session", Description = "Session state snapshot.", ProducedByStates = ["created", "prepared", "running", "ready", "stopped", "disposed"] }, new AdapterArtifactType { Type = "endpoint", Description = "Protocol endpoint snapshot.", ProducedByStates = ["prepared", "running", "ready"] }],
        MetricsAvailability = new AdapterMetricsAvailability { Available = true, SessionMetricsAvailable = true, EndpointMetricsAvailable = true, ProcessMetricsAvailable = true, ContainerMetricsAvailable = false, AvailableKinds = ["snapshot"] },
        DefaultResponseContentTypes = [options.DefaultControlPlaneContentType]
    });

    public Task<AdapterSessionResource> CreateSessionAsync(AdapterSessionCreateRequest request)
    {
        var sessionId = !string.IsNullOrWhiteSpace(request.RequestedSessionId) ? request.RequestedSessionId! : BuildSessionId();
        lock (gate)
        {
            deletedSessions.Remove(sessionId);
            var session = new IncursaRawQuicSession(sessionId, CreateSessionDirectory(request.RunId, request.CellId, sessionId)) { Summary = new AdapterSessionSummary { SessionId = sessionId, State = AdapterSessionState.Created, RunId = request.RunId, CellId = request.CellId, CreatedAt = Now(), UpdatedAt = Now() } };
            sessions[sessionId] = session;
            session.WriteSessionSnapshot();
            return Task.FromResult(new AdapterSessionResource { Session = session.Summary, Operation = new AdapterOperationResult { Category = AdapterOperationResultCategory.Succeeded, Message = "Session created." } });
        }
    }

    public Task<AdapterSessionResource> GetSessionAsync(string sessionId) { var s = GetSession(sessionId); return Task.FromResult(new AdapterSessionResource { Session = s.Summary, Operation = s.LastOperation }); }

    public Task<AdapterOperationResult> PrepareAsync(string sessionId, AdapterPrepareRequest request)
    {
        var session = GetSession(sessionId);
        lock (session.Gate)
        {
            if (session.Summary.State is AdapterSessionState.Preparing or AdapterSessionState.Starting or AdapterSessionState.Running or AdapterSessionState.Ready)
                throw CreateProblem("invalid-transition", StatusCodes.Status409Conflict, "Session is already prepared or running.", "prepare", sessionId);
            var scenario = NormalizeScenario(request, DeserializeScenario(request.ScenarioDocument));
            var requestedProtocol = ResolveRequestedProtocol(request, scenario);
            var support = EvaluateSupport(scenario, requestedProtocol);
            session.Scenario = scenario; session.RequestedProtocol = requestedProtocol; session.RequestedEndpointBindings = request.RequestedEndpointBindings; session.ArtifactOutputExpectations = request.ArtifactOutputExpectations; session.Extensions = request.Extensions;
            session.Summary = session.Summary with { ScenarioId = request.ScenarioId, ScenarioVersion = request.ScenarioVersion, Role = request.Role, RunId = request.RunId, CellId = request.CellId, UpdatedAt = Now(), Warnings = support.Warnings };
            if (!support.IsSupported)
            {
                session.Summary = session.Summary with { State = AdapterSessionState.Unsupported };
                session.LastOperation = new AdapterOperationResult { Category = AdapterOperationResultCategory.Unsupported, Message = support.Reason, Code = "unsupported", Warnings = support.Warnings };
                session.WriteSessionSnapshot(); return Task.FromResult(session.LastOperation);
            }
            session.EndpointPlan = new IncursaRawQuicEndpointPlan(options.QuicAlpn, options.CertificateSubject, options.QuicPort, scenario);
            session.Summary = session.Summary with { State = AdapterSessionState.Prepared };
            session.LastOperation = new AdapterOperationResult { Category = AdapterOperationResultCategory.Succeeded, Message = "Session prepared." };
            session.WriteSessionSnapshot(); return Task.FromResult(session.LastOperation);
        }
    }

    public async Task<AdapterOperationResult> StartAsync(string sessionId)
    {
        var session = GetSession(sessionId);
        lock (session.Gate)
        {
            if (session.Summary.State == AdapterSessionState.Created) throw CreateProblem("invalid-transition", StatusCodes.Status409Conflict, "Session must be prepared before start.", "start", sessionId);
            if (session.Summary.State == AdapterSessionState.Unsupported)
            {
                session.LastOperation ??= new AdapterOperationResult { Category = AdapterOperationResultCategory.Unsupported, Message = "Session was marked unsupported during prepare.", Code = "unsupported" };
                return session.LastOperation;
            }
            if (session.EndpointProcess is not null) return session.LastOperation ?? new AdapterOperationResult { Category = AdapterOperationResultCategory.Succeeded, Message = "Session already started." };
            if (session.EndpointPlan is null) throw CreateProblem("invalid-transition", StatusCodes.Status409Conflict, "Session must be prepared before start.", "start", sessionId);
            session.Summary = session.Summary with { State = AdapterSessionState.Starting, UpdatedAt = Now() };
            session.WriteSessionSnapshot();
        }
        IncursaRawQuicEndpointProcess ep;
        try { ep = await IncursaRawQuicProtocolEndpointLauncher.StartAsync(options.RepositoryRoot, session, session.EndpointPlan!, options.BenchmarkServerProjectPath, default); }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or IOException)
        {
            lock (session.Gate) { session.Summary = session.Summary with { State = AdapterSessionState.Failed, UpdatedAt = Now() }; session.LastOperation = new AdapterOperationResult { Category = AdapterOperationResultCategory.Failed, Message = ex.Message, Code = "start-failed" }; session.WriteSessionSnapshot(); return session.LastOperation; }
        }
        lock (session.Gate) { session.EndpointProcess = ep; session.Endpoint = ep.Endpoint; session.WriteEndpointSnapshot(); }
        var readiness = await WaitForReadinessAsync(session, ep);
        IncursaRawQuicEndpointProcess? toStop = null;
        lock (session.Gate)
        {
            if (readiness.IsReady) { session.Summary = session.Summary with { State = AdapterSessionState.Ready, UpdatedAt = Now() }; session.LastOperation = new AdapterOperationResult { Category = AdapterOperationResultCategory.Succeeded, Message = "Session started." }; }
            else { toStop = session.EndpointProcess; session.EndpointProcess = null; session.Summary = session.Summary with { State = readiness.IsUnsupported ? AdapterSessionState.Unsupported : AdapterSessionState.Failed, UpdatedAt = Now() }; session.LastOperation = new AdapterOperationResult { Category = readiness.IsUnsupported ? AdapterOperationResultCategory.Unsupported : AdapterOperationResultCategory.Failed, Message = readiness.Message, Code = readiness.IsUnsupported ? "unsupported" : "readiness-failed", Warnings = readiness.Warnings }; }
            session.WriteSessionSnapshot();
        }
        if (toStop is not null) await toStop.StopAsync();
        lock (session.Gate) { session.WriteSessionSnapshot(); return session.LastOperation!; }
    }

    public Task<AdapterStatusResponse> GetStatusAsync(string sessionId)
    {
        var session = GetSession(sessionId);
        lock (session.Gate)
        {
            var readiness = session.Summary.State switch
            {
                AdapterSessionState.Ready => new AdapterReadinessSnapshot { Status = AdapterReadinessStatus.Ready, Message = "Incursa raw QUIC endpoint ready.", ObservedAt = Now(), Warnings = session.Summary.Warnings },
                AdapterSessionState.Unsupported => new AdapterReadinessSnapshot { Status = AdapterReadinessStatus.Unsupported, Message = session.LastOperation?.Message ?? "Unsupported scenario.", ObservedAt = Now(), Warnings = session.Summary.Warnings },
                AdapterSessionState.Failed => new AdapterReadinessSnapshot { Status = AdapterReadinessStatus.Failed, Message = session.LastOperation?.Message ?? "Endpoint not ready.", ObservedAt = Now(), Warnings = session.Summary.Warnings },
                AdapterSessionState.Running or AdapterSessionState.Starting or AdapterSessionState.Prepared => new AdapterReadinessSnapshot { Status = AdapterReadinessStatus.NotReady, Message = "Endpoint is not ready yet.", ObservedAt = Now(), Warnings = session.Summary.Warnings },
                _ => new AdapterReadinessSnapshot { Status = AdapterReadinessStatus.Unknown, Message = "Session has not been started.", ObservedAt = Now(), Warnings = session.Summary.Warnings }
            };
            return Task.FromResult(new AdapterStatusResponse { Session = session.Summary, Readiness = readiness, Health = new AdapterHealthSnapshot { Status = AdapterHealthStatus.Ready, Message = "Incursa raw QUIC adapter ready.", ObservedAt = Now() }, Operation = session.LastOperation });
        }
    }

    public Task<AdapterEndpointsResponse> GetEndpointsAsync(string sessionId)
    {
        var session = GetSession(sessionId);
        lock (session.Gate)
        {
            IReadOnlyList<AdapterEndpoint> eps = session.Endpoint is null ? [] : [session.Endpoint];
            return Task.FromResult(new AdapterEndpointsResponse { Session = session.Summary, Endpoints = eps, Operation = new AdapterOperationResult { Category = session.Summary.State == AdapterSessionState.Unsupported ? AdapterOperationResultCategory.Unsupported : AdapterOperationResultCategory.Succeeded, Message = session.Endpoint is null ? "No endpoint available." : "Protocol endpoint discovered.", Warnings = session.Summary.Warnings } });
        }
    }

    public Task<AdapterMetricsResponse> GetMetricsAsync(string sessionId)
    {
        var session = GetSession(sessionId);
        lock (session.Gate)
        {
            var metrics = new List<AdapterMetric>();
            if (session.EndpointProcess is not null) metrics.AddRange(CreateProcessMetrics(session.EndpointProcess));
            return Task.FromResult(new AdapterMetricsResponse { Session = session.Summary, Availability = session.Summary.State == AdapterSessionState.Unsupported ? AdapterResourceAvailability.Unsupported : AdapterResourceAvailability.Available, CapturedAt = Now(), Metrics = metrics, Notes = session.Summary.State == AdapterSessionState.Unsupported ? ["Session was marked unsupported."] : [], Operation = new AdapterOperationResult { Category = session.Summary.State == AdapterSessionState.Unsupported ? AdapterOperationResultCategory.Unsupported : AdapterOperationResultCategory.Succeeded, Message = session.Summary.State == AdapterSessionState.Unsupported ? "Metrics unavailable for unsupported session." : "Metrics snapshot captured." } });
        }
    }

    public Task<AdapterArtifactsResponse> GetArtifactsAsync(string sessionId)
    {
        var session = GetSession(sessionId);
        lock (session.Gate) { return Task.FromResult(new AdapterArtifactsResponse { Session = session.Summary, Availability = session.Summary.State == AdapterSessionState.Unsupported ? AdapterResourceAvailability.Unsupported : AdapterResourceAvailability.Available, Artifacts = BuildArtifacts(session), Operation = new AdapterOperationResult { Category = session.Summary.State == AdapterSessionState.Unsupported ? AdapterOperationResultCategory.Unsupported : AdapterOperationResultCategory.Succeeded, Message = "Artifacts discovered." } }); }
    }

    public async Task<AdapterOperationResult> StopAsync(string sessionId)
    {
        var session = GetSession(sessionId); var orig = session.Summary.State;
        IncursaRawQuicEndpointProcess? ep;
        lock (session.Gate) { ep = session.EndpointProcess; session.Summary = session.Summary with { State = AdapterSessionState.Stopping, UpdatedAt = Now() }; session.WriteSessionSnapshot(); }
        if (ep is not null) await ep.StopAsync();
        lock (session.Gate)
        {
            session.Summary = session.Summary with { State = orig == AdapterSessionState.Unsupported ? AdapterSessionState.Unsupported : AdapterSessionState.Stopped, UpdatedAt = Now() };
            session.LastOperation = new AdapterOperationResult { Category = orig == AdapterSessionState.Unsupported ? AdapterOperationResultCategory.Unsupported : AdapterOperationResultCategory.Succeeded, Message = "Session stopped." };
            session.WriteSessionSnapshot(); return session.LastOperation;
        }
    }

    public async Task<AdapterSessionResource> DeleteSessionAsync(string sessionId)
    {
        var session = GetOrCreateDeletedSession(sessionId);
        await StopIfNeededAsync(session);
        lock (gate) { deletedSessions.Add(sessionId); sessions.TryRemove(sessionId, out _); }
        lock (session.Gate) { session.Summary = session.Summary with { State = AdapterSessionState.Disposed, UpdatedAt = Now() }; session.LastOperation = new AdapterOperationResult { Category = AdapterOperationResultCategory.Succeeded, Message = "Session deleted." }; session.WriteSessionSnapshot(); return new AdapterSessionResource { Session = session.Summary, Operation = session.LastOperation }; }
    }

    private async Task StopIfNeededAsync(IncursaRawQuicSession session) { IncursaRawQuicEndpointProcess? ep; lock (session.Gate) { ep = session.EndpointProcess; session.EndpointProcess = null; } if (ep is not null) await ep.StopAsync(); }

    private IncursaRawQuicSession GetOrCreateDeletedSession(string sessionId)
    {
        if (sessions.TryGetValue(sessionId, out var s)) return s;
        lock (gate)
        {
            if (sessions.TryGetValue(sessionId, out s)) return s;
            if (deletedSessions.Contains(sessionId)) return new IncursaRawQuicSession(sessionId, CreateSessionDirectory(null, null, sessionId)) { Summary = new AdapterSessionSummary { SessionId = sessionId, State = AdapterSessionState.Disposed, UpdatedAt = Now() } };
            throw CreateProblem("session-not-found", StatusCodes.Status404NotFound, "Unknown session.", "session", sessionId);
        }
    }

    private IncursaRawQuicSession GetSession(string sessionId)
    {
        if (sessions.TryGetValue(sessionId, out var s)) return s;
        lock (gate) { if (sessions.TryGetValue(sessionId, out s)) return s; if (deletedSessions.Contains(sessionId)) throw CreateProblem("session-not-found", StatusCodes.Status404NotFound, "Unknown session.", "session", sessionId); }
        throw CreateProblem("session-not-found", StatusCodes.Status404NotFound, "Unknown session.", "session", sessionId);
    }

    private AdapterIdentity CreateAdapterIdentity() => new() { Id = options.AdapterIdentityId, Name = options.AdapterIdentityName, Version = options.AdapterIdentityVersion, Vendor = "Incursa" };
    private AdapterIdentity CreateImplementationIdentity() => new() { Id = options.ImplementationId, Name = options.ImplementationName, Version = options.ImplementationVersion, Image = options.ImplementationImage };
    private AdapterVersionCompatibility CreateCompatibility() => new() { ContractVersion = options.ContractVersion, CompatibleContractVersions = [options.ContractVersion] };

    private IReadOnlyList<AdapterCapability> CreateCapabilities() => [new AdapterCapability { Id = "adapter-control-plane", Status = AdapterCapabilityStatus.Supported, Description = "ProtocolLab Adapter Contract v1 control plane." }, new AdapterCapability { Id = "quic.server", Status = AdapterCapabilityStatus.Supported, Description = "Raw QUIC server endpoint using Incursa raw QUIC server process." }, new AdapterCapability { Id = "quicTransport", Status = AdapterCapabilityStatus.Supported, Description = "Raw QUIC transport support." }, new AdapterCapability { Id = "quicHandshake", Status = AdapterCapabilityStatus.Supported, Description = "QUIC connection handshake support." }, new AdapterCapability { Id = "quicStreams", Status = AdapterCapabilityStatus.Supported, Description = "QUIC bidirectional stream support." }, new AdapterCapability { Id = "quicMultiplexing", Status = AdapterCapabilityStatus.Supported, Description = "QUIC multiplexed stream fan-out support." }, new AdapterCapability { Id = "quicDuplex", Status = AdapterCapabilityStatus.Supported, Description = "QUIC bidirectional stream payload support." }];

    private IncursaRawQuicScenarioSupport EvaluateSupport(ScenarioDefinition scenario, string requestedProtocol)
    {
        var warnings = new List<string>();
        if (!string.Equals(scenario.ImplementationRole, "server", StringComparison.OrdinalIgnoreCase)) return IncursaRawQuicScenarioSupport.Unsupported("Only server scenarios are supported.", warnings);
        if (!string.Equals(scenario.Family, "quic.transport", StringComparison.OrdinalIgnoreCase)) return IncursaRawQuicScenarioSupport.Unsupported("Only 'quic.transport' family scenarios are supported.", warnings);
        if (!IsSupportedScenario(scenario.Id)) return IncursaRawQuicScenarioSupport.Unsupported($"Scenario '{scenario.Id}' is not supported.", warnings);
        if (!string.Equals(requestedProtocol, "quic", StringComparison.OrdinalIgnoreCase)) return IncursaRawQuicScenarioSupport.Unsupported($"Protocol '{requestedProtocol}' is not supported.", warnings);
        foreach (var c in scenario.RequiredCapabilities) { if (!SupportedCapabilities.Contains(c)) return IncursaRawQuicScenarioSupport.Unsupported($"Capability '{c}' is not supported.", warnings); }
        return IncursaRawQuicScenarioSupport.Supported(warnings);
    }

    private static bool IsSupportedScenario(string id) => SupportedScenarios.Contains(id);
    private static readonly HashSet<string> SupportedScenarios = new(StringComparer.OrdinalIgnoreCase) { "quic.transport.handshake-cold", "quic.transport.latency.echo-1kb", "quic.transport.connection-churn", "quic.transport.stream-churn", "quic.transport.stream-throughput.1mb", "quic.transport.multiplex.100x64kb", "quic.transport.stream-limits.100x64kb", "quic.transport.flow-control.slow-reader-16x64kb", "quic.transport.duplex-streams", "quic.transport.duplex-streams-peer-matrix" };
    private static readonly HashSet<string> SupportedCapabilities = new(StringComparer.OrdinalIgnoreCase) { "quicTransport", "quicHandshake", "quicStreams", "quicMultiplexing", "quicDuplex" };

    private async Task<IncursaRawQuicReadinessResult> WaitForReadinessAsync(IncursaRawQuicSession session, IncursaRawQuicEndpointProcess ep)
    {
        var deadline = Now() + options.ReadinessTimeout;
        var errors = new List<string>();
        while (Now() < deadline)
        {
            if (ep.HasExited) return IncursaRawQuicReadinessResult.Failed($"Server exited before readiness with code {ep.ExitCode}.", errors);
            if (ep.IsReady) return IncursaRawQuicReadinessResult.Ready(errors);
            await Task.Delay(300);
        }
        return IncursaRawQuicReadinessResult.Failed($"Server did not become ready within {options.ReadinessTimeout.TotalSeconds:0}s.", errors);
    }

    private IReadOnlyList<AdapterArtifact> BuildArtifacts(IncursaRawQuicSession s)
    {
        var list = new List<AdapterArtifact> { new() { ArtifactId = "server.stdout", ArtifactType = "stdout", Status = s.EndpointProcess is null ? AdapterResourceAvailability.Unavailable : AdapterResourceAvailability.Available, Path = s.StdoutPath, ContentType = "text/plain", Final = true }, new() { ArtifactId = "server.stderr", ArtifactType = "stderr", Status = s.EndpointProcess is null ? AdapterResourceAvailability.Unavailable : AdapterResourceAvailability.Available, Path = s.StderrPath, ContentType = "text/plain", Final = true }, new() { ArtifactId = "session.snapshot", ArtifactType = "session", Status = AdapterResourceAvailability.Available, Path = s.SessionSnapshotPath, ContentType = "application/json", Final = true } };
        if (!string.IsNullOrWhiteSpace(s.EndpointSnapshotPath)) list.Add(new AdapterArtifact { ArtifactId = "endpoint.snapshot", ArtifactType = "endpoint", Status = AdapterResourceAvailability.Available, Path = s.EndpointSnapshotPath, ContentType = "application/json", Final = true });
        return list;
    }

    private IReadOnlyList<AdapterMetric> CreateProcessMetrics(IncursaRawQuicEndpointProcess ep)
    {
        ep.Refresh(); var jsonOpts = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        return [new AdapterMetric { MetricId = "process.id", Scope = "session", Value = JsonSerializer.SerializeToElement(ep.ProcessId, jsonOpts), Notes = "Child Incursa raw QUIC server process id." }, new AdapterMetric { MetricId = "process.working-set-bytes", Scope = "process", Value = JsonSerializer.SerializeToElement(ep.WorkingSetBytes ?? 0L, jsonOpts), Notes = "Child server working set." }, new AdapterMetric { MetricId = "process.cpu-seconds", Scope = "process", Value = JsonSerializer.SerializeToElement(ep.CpuSeconds ?? 0d, jsonOpts), Notes = "Child server accumulated CPU time." }, new AdapterMetric { MetricId = "endpoint.port", Scope = "endpoint", Value = JsonSerializer.SerializeToElement(ep.Endpoint.Port, jsonOpts), Notes = "QUIC endpoint port." }];
    }

    private ScenarioDefinition DeserializeScenario(JsonElement d)
    {
        try
        {
            var raw = d.GetRawText();
            if (string.IsNullOrEmpty(raw)) throw new InvalidOperationException("Empty scenario document.");
            return JsonSerializer.Deserialize<ScenarioDefinition>(raw, new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? throw CreateProblem("invalid-scenario", StatusCodes.Status400BadRequest, "Could not parse scenario document.", "prepare");
        }
        catch (InvalidOperationException) { throw CreateProblem("invalid-scenario", StatusCodes.Status400BadRequest, "Invalid scenario document.", "prepare"); }
        catch (System.Text.Json.JsonException ex) { throw CreateProblem("invalid-scenario", StatusCodes.Status400BadRequest, $"Invalid scenario document: {ex.Message}", "prepare"); }
    }
    private static ScenarioDefinition NormalizeScenario(AdapterPrepareRequest r, ScenarioDefinition s)
    {
        if (!string.IsNullOrWhiteSpace(s.Id)) return s;
        return new ScenarioDefinition { Id = r.ScenarioId, Name = r.ScenarioId, Version = r.ScenarioVersion, Description = r.ScenarioId, ImplementationRole = r.Role, Protocol = s.Protocol, RequiredCapabilities = s.RequiredCapabilities, Endpoint = s.Endpoint, H3Protocol = s.H3Protocol, QuicTransport = s.QuicTransport, WebTransport = s.WebTransport, Masque = s.Masque, Validation = s.Validation, Benchmark = s.Benchmark, NetworkProfile = s.NetworkProfile, RequiredMetrics = s.RequiredMetrics, ArtifactRequirements = s.ArtifactRequirements, Tags = s.Tags };
    }
    private string ResolveRequestedProtocol(AdapterPrepareRequest r, ScenarioDefinition s) => r.RequestedEndpointBindings.FirstOrDefault()?.EndpointType ?? s.Protocol;
    private string CreateSessionDirectory(string? runId, string? cellId, string sessionId) { var segs = new List<string> { options.RepositoryRoot, ".artifacts", "runs" }; if (!string.IsNullOrWhiteSpace(runId)) segs.Add(ArtifactLayout.SanitizeSegment(runId)); if (!string.IsNullOrWhiteSpace(cellId)) segs.Add(ArtifactLayout.SanitizeSegment(cellId)); segs.Add("adapter"); segs.Add(ArtifactLayout.SanitizeSegment(sessionId)); var dir = Path.Combine(segs.ToArray()); Directory.CreateDirectory(dir); return dir; }
    private string BuildSessionId() { lock (gate) { sessionCounter++; return $"incursa-raw-quic-adapter-{sessionCounter:0000}"; } }
    private DateTimeOffset Now() => options.TimeProvider.GetUtcNow();
    private static IncursaRawQuicAdapterProblemException CreateProblem(string code, int status, string title, string op, string? sid = null) => new(new AdapterProblemDetails { Type = "https://incursa.example/problems/incursa-raw-quic-adapter", Title = title, Status = status, Code = code, Operation = op, SessionId = sid, Retryable = false }, (HttpStatusCode)status);
}

public sealed class IncursaRawQuicAdapterProblemException : Exception
{
    public IncursaRawQuicAdapterProblemException(AdapterProblemDetails problem, HttpStatusCode statusCode) : base(problem.Title) { Problem = problem; StatusCode = statusCode; }
    public AdapterProblemDetails Problem { get; }
    public HttpStatusCode StatusCode { get; }
}

internal sealed class IncursaRawQuicSession
{
    public IncursaRawQuicSession(string sessionId, string dir) { SessionId = sessionId; SessionDirectory = dir; SessionSnapshotPath = Path.Combine(dir, "session.json"); EndpointSnapshotPath = Path.Combine(dir, "endpoint.json"); StdoutPath = Path.Combine(dir, "server.stdout.txt"); StderrPath = Path.Combine(dir, "server.stderr.txt"); CommandLinePath = Path.Combine(dir, "server.command.txt"); Directory.CreateDirectory(dir); }
    public string SessionId { get; } public string SessionDirectory { get; } public string SessionSnapshotPath { get; } public string EndpointSnapshotPath { get; } public string StdoutPath { get; } public string StderrPath { get; } public string CommandLinePath { get; }
    public object Gate { get; } = new(); public AdapterSessionSummary Summary { get; set; } = new(); public AdapterOperationResult? LastOperation { get; set; }
    public ScenarioDefinition? Scenario { get; set; } public string? RequestedProtocol { get; set; }
    public IReadOnlyList<AdapterEndpointBinding> RequestedEndpointBindings { get; set; } = []; public IReadOnlyList<AdapterArtifactExpectation> ArtifactOutputExpectations { get; set; } = [];
    public Dictionary<string, JsonElement> Extensions { get; set; } = [];
    public IncursaRawQuicEndpointPlan? EndpointPlan { get; set; } public AdapterEndpoint? Endpoint { get; set; } public IncursaRawQuicEndpointProcess? EndpointProcess { get; set; }
    public void WriteSessionSnapshot() => File.WriteAllText(SessionSnapshotPath, JsonSerializer.Serialize(Summary, ProtocolLabAdapterJson.Options));
    public void WriteEndpointSnapshot() { if (Endpoint is null) return; File.WriteAllText(EndpointSnapshotPath, JsonSerializer.Serialize(Endpoint, ProtocolLabAdapterJson.Options)); File.WriteAllText(CommandLinePath, EndpointProcess?.CommandLine ?? string.Empty); }
}

internal sealed record IncursaRawQuicEndpointPlan(string Alpn, string CertificateSubject, int Port, ScenarioDefinition Scenario);
internal sealed record IncursaRawQuicReadinessResult(bool IsReady, bool IsUnsupported, string Message, IReadOnlyList<string> Warnings) { public static IncursaRawQuicReadinessResult Ready(IReadOnlyList<string> w) => new(true, false, "Incursa raw QUIC server is ready.", w); public static IncursaRawQuicReadinessResult Failed(string m, IReadOnlyList<string> w) => new(false, false, m, w); }
internal sealed record IncursaRawQuicScenarioSupport(bool IsSupported, string? Reason, IReadOnlyList<string> Warnings) { public static IncursaRawQuicScenarioSupport Supported(IReadOnlyList<string> w) => new(true, null, w); public static IncursaRawQuicScenarioSupport Unsupported(string r, IReadOnlyList<string> w) => new(false, r, w); }
