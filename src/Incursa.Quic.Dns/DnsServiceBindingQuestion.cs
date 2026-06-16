// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents a DNS question from a service binding response.
/// </summary>
public sealed class DnsServiceBindingQuestion
{
    internal DnsServiceBindingQuestion(string name, ushort type, ushort dnsClass)
    {
        Name = name;
        Type = type;
        Class = dnsClass;
    }

    /// <summary>
    /// Gets the question name.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the question type.
    /// </summary>
    public ushort Type { get; }

    /// <summary>
    /// Gets the question class.
    /// </summary>
    public ushort Class { get; }
}
