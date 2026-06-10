// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using Incursa.ProtocolLab.Adapter.Contracts;
using Incursa.ProtocolLab.Adapters.IncursaRawQuic;
using Microsoft.AspNetCore.Http;

static string ResolveRepositoryRoot(string contentRootPath)
{
    var directory = new DirectoryInfo(contentRootPath);
    while (directory is not null)
    {
        if (File.Exists(Path.Combine(directory.FullName, "Incursa.Quic.slnx")))
        {
            return directory.FullName;
        }

        directory = directory.Parent;
    }

    return contentRootPath;
}

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton(new IncursaRawQuicAdapterRuntime(new IncursaRawQuicAdapterOptions
{
    RepositoryRoot = ResolveRepositoryRoot(builder.Environment.ContentRootPath),
    ControlPlaneBaseUrl = builder.Configuration["ASPNETCORE_URLS"] ?? ""
}));
var app = builder.Build();
var group = app.MapGroup(AdapterRoutes.Prefix);

group.MapGet("/health", async (IncursaRawQuicAdapterRuntime r) => Results.Json(await r.GetHealthAsync(), ProtocolLabAdapterJson.Options));
group.MapGet("/manifest", async (IncursaRawQuicAdapterRuntime r) => Results.Json(await r.GetManifestAsync(), ProtocolLabAdapterJson.Options));
group.MapPost("/sessions", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r) =>
{
    try { var req = await ReadBodyAsync<AdapterSessionCreateRequest>(ctx.Request); await WriteJsonAsync(ctx, await r.CreateSessionAsync(req), 201); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapGet("/sessions/{sessionId}", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { await WriteJsonAsync(ctx, await r.GetSessionAsync(sessionId)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapPost("/sessions/{sessionId}/prepare", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { var req = await ReadBodyAsync<AdapterPrepareRequest>(ctx.Request); await WriteJsonAsync(ctx, await r.PrepareAsync(sessionId, req)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapPost("/sessions/{sessionId}/start", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { await WriteJsonAsync(ctx, await r.StartAsync(sessionId)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapGet("/sessions/{sessionId}/status", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { await WriteJsonAsync(ctx, await r.GetStatusAsync(sessionId)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapGet("/sessions/{sessionId}/endpoints", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { await WriteJsonAsync(ctx, await r.GetEndpointsAsync(sessionId)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapGet("/sessions/{sessionId}/metrics", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { await WriteJsonAsync(ctx, await r.GetMetricsAsync(sessionId)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapGet("/sessions/{sessionId}/artifacts", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { await WriteJsonAsync(ctx, await r.GetArtifactsAsync(sessionId)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapPost("/sessions/{sessionId}/stop", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { await WriteJsonAsync(ctx, await r.StopAsync(sessionId)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
group.MapDelete("/sessions/{sessionId}", async Task (HttpContext ctx, IncursaRawQuicAdapterRuntime r, string sessionId) =>
{
    try { await WriteJsonAsync(ctx, await r.DeleteSessionAsync(sessionId)); }
    catch (IncursaRawQuicAdapterProblemException ex) { await WriteProblemAsync(ctx, ex); }
});
app.Run();

static async Task<T> ReadBodyAsync<T>(HttpRequest request)
{
    request.EnableBuffering();
    using var sr = new StreamReader(request.Body, leaveOpen: true);
    var text = await sr.ReadToEndAsync();
    return JsonSerializer.Deserialize<T>(text, new JsonSerializerOptions(JsonSerializerDefaults.Web))
        ?? throw new IncursaRawQuicAdapterProblemException(new AdapterProblemDetails { Title = "Null body", Status = 400, Code = "null-body" }, System.Net.HttpStatusCode.BadRequest);
}

static async Task WriteJsonAsync(HttpContext ctx, object value, int statusCode = 200)
{
    ctx.Response.StatusCode = statusCode;
    ctx.Response.ContentType = "application/json; charset=utf-8";
    var json = JsonSerializer.Serialize(value, ProtocolLabAdapterJson.Options);
    await ctx.Response.WriteAsync(json);
}

static async Task WriteProblemAsync(HttpContext ctx, IncursaRawQuicAdapterProblemException ex)
{
    ctx.Response.StatusCode = (int)ex.StatusCode;
    ctx.Response.ContentType = "application/json; charset=utf-8";
    var json = JsonSerializer.Serialize(ex.Problem, ProtocolLabAdapterJson.Options);
    await ctx.Response.WriteAsync(json);
}

public partial class Program;
