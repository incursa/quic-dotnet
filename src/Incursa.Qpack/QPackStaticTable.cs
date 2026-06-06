// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Qpack;

/// <summary>
/// Exposes the RFC 9204 QPACK static table.
/// </summary>
public static class QPackStaticTable
{
    // CONTEXT: RFC 9204 static-table order is wire-visible because encoder and decoder lookups use
    // the published zero-based indices, so this array must stay in the exact table order.
    // SEE: spec:REQ-QUIC-RFC9204-S2-0001
    // SEE: code:src/Incursa.Qpack/QPackEncoder.cs#EncodeFieldSection
    // SEE: code:src/Incursa.Qpack/QPackDecoder.cs#DecodeFieldSection
    private static readonly QPackFieldLine[] Entries =
    [
        new(":authority", ""),
        new(":path", "/"),
        new("age", "0"),
        new("content-disposition", ""),
        new("content-length", "0"),
        new("cookie", ""),
        new("date", ""),
        new("etag", ""),
        new("if-modified-since", ""),
        new("if-none-match", ""),
        new("last-modified", ""),
        new("link", ""),
        new("location", ""),
        new("referer", ""),
        new("set-cookie", ""),
        new(":method", "CONNECT"),
        new(":method", "DELETE"),
        new(":method", "GET"),
        new(":method", "HEAD"),
        new(":method", "OPTIONS"),
        new(":method", "POST"),
        new(":method", "PUT"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "103"),
        new(":status", "200"),
        new(":status", "304"),
        new(":status", "404"),
        new(":status", "503"),
        new("accept", "*/*"),
        new("accept", "application/dns-message"),
        new("accept-encoding", "gzip, deflate, br"),
        new("accept-ranges", "bytes"),
        new("access-control-allow-headers", "cache-control"),
        new("access-control-allow-headers", "content-type"),
        new("access-control-allow-origin", "*"),
        new("cache-control", "max-age=0"),
        new("cache-control", "max-age=2592000"),
        new("cache-control", "max-age=604800"),
        new("cache-control", "no-cache"),
        new("cache-control", "no-store"),
        new("cache-control", "public, max-age=31536000"),
        new("content-encoding", "br"),
        new("content-encoding", "gzip"),
        new("content-type", "application/dns-message"),
        new("content-type", "application/javascript"),
        new("content-type", "application/json"),
        new("content-type", "application/x-www-form-urlencoded"),
        new("content-type", "image/gif"),
        new("content-type", "image/jpeg"),
        new("content-type", "image/png"),
        new("content-type", "text/css"),
        new("content-type", "text/html; charset=utf-8"),
        new("content-type", "text/plain"),
        new("content-type", "text/plain;charset=utf-8"),
        new("range", "bytes=0-"),
        new("strict-transport-security", "max-age=31536000"),
        new("strict-transport-security", "max-age=31536000; includesubdomains"),
        new("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        new("vary", "accept-encoding"),
        new("vary", "origin"),
        new("x-content-type-options", "nosniff"),
        new("x-xss-protection", "1; mode=block"),
        new(":status", "100"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "302"),
        new(":status", "400"),
        new(":status", "403"),
        new(":status", "421"),
        new(":status", "425"),
        new(":status", "500"),
        new("accept-language", ""),
        new("access-control-allow-credentials", "FALSE"),
        new("access-control-allow-credentials", "TRUE"),
        new("access-control-allow-headers", "*"),
        new("access-control-allow-methods", "get"),
        new("access-control-allow-methods", "get, post, options"),
        new("access-control-allow-methods", "options"),
        new("access-control-expose-headers", "content-length"),
        new("access-control-request-headers", "content-type"),
        new("access-control-request-method", "get"),
        new("access-control-request-method", "post"),
        new("alt-svc", "clear"),
        new("authorization", ""),
        new("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        new("early-data", "1"),
        new("expect-ct", ""),
        new("forwarded", ""),
        new("if-range", ""),
        new("origin", ""),
        new("purpose", "prefetch"),
        new("server", ""),
        new("timing-allow-origin", "*"),
        new("upgrade-insecure-requests", "1"),
        new("user-agent", ""),
        new("x-forwarded-for", ""),
        new("x-frame-options", "deny"),
        new("x-frame-options", "sameorigin"),
    ];

    /// <summary>
    /// Gets the number of entries in the RFC 9204 static table.
    /// </summary>
    public static int Count => Entries.Length;

    /// <summary>
    /// Tries to get a static table field line by zero-based index.
    /// </summary>
    public static bool TryGet(int index, out QPackFieldLine fieldLine)
    {
        if ((uint)index >= (uint)Entries.Length)
        {
            fieldLine = default;
            return false;
        }

        fieldLine = Entries[index];
        return true;
    }

    internal static QPackFieldLine GetRequired(ulong index)
    {
        if (index > int.MaxValue || !TryGet((int)index, out QPackFieldLine fieldLine))
        {
            throw new QPackException(QPackErrorCode.DecompressionFailed, "The QPACK static table index is invalid.");
        }

        return fieldLine;
    }

    internal static int FindFieldLineIndex(QPackFieldLine fieldLine)
    {
        for (int index = 0; index < Entries.Length; index++)
        {
            if (StringComparer.Ordinal.Equals(Entries[index].Name, fieldLine.Name)
                && StringComparer.Ordinal.Equals(Entries[index].Value, fieldLine.Value))
            {
                return index;
            }
        }

        return -1;
    }

    internal static int FindNameIndex(string name)
    {
        for (int index = 0; index < Entries.Length; index++)
        {
            if (StringComparer.Ordinal.Equals(Entries[index].Name, name))
            {
                return index;
            }
        }

        return -1;
    }
}
