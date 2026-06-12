// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9250_0026_ErrorCodes
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0026")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NoErrorCodeValueAndNormalizationMatchRegistry()
    {
        AssertRegisteredErrorCode(DoqErrorCode.NoError, 0x0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0026")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SpecificErrorCodesDoNotNormalizeAsNoError()
    {
        Assert.NotEqual(DoqErrorCode.NoError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.InternalError));
        Assert.NotEqual(DoqErrorCode.NoError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x100));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0027")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientConnectionCloseWithoutErrorUsesNoError()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");

        Assert.Contains("CloseAsync((long)DoqErrorCode.NoError", client, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0027")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolFailureCloseDoesNotUseNoError()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");

        Assert.Contains("CloseConnectionAsync(activeConnection, DoqErrorCode.ProtocolError", client, StringComparison.Ordinal);
        Assert.Contains("CloseConnectionAsync(connection, DoqErrorCode.ProtocolError", server, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0028")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InternalErrorCodeValueAndUsageMatchRegistry()
    {
        AssertRegisteredErrorCode(DoqErrorCode.InternalError, 0x1);

        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        Assert.Contains("AbortStreamWrite(stream, DoqErrorCode.InternalError)", server, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0028")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolErrorCodeDoesNotNormalizeAsInternalError()
    {
        Assert.NotEqual(DoqErrorCode.InternalError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ProtocolError));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0029")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtocolErrorCodeValueAndUsageMatchRegistry()
    {
        AssertRegisteredErrorCode(DoqErrorCode.ProtocolError, 0x2);

        string stream = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqStream.cs");
        Assert.Contains("DoqErrorCode.ProtocolError", stream, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0029")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NoErrorCodeDoesNotNormalizeAsProtocolError()
    {
        Assert.NotEqual(DoqErrorCode.ProtocolError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.NoError));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0030")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestCancelledCodeValueAndUsageMatchRegistry()
    {
        AssertRegisteredErrorCode(DoqErrorCode.RequestCancelled, 0x3);

        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        Assert.Contains("AbortStreamRead(stream, DoqErrorCode.RequestCancelled)", client, StringComparison.Ordinal);
        Assert.Contains("AbortStreamWrite(stream, DoqErrorCode.RequestCancelled)", server, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0030")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolErrorCodeDoesNotNormalizeAsRequestCancelled()
    {
        Assert.NotEqual(DoqErrorCode.RequestCancelled, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ProtocolError));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0031")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExcessiveLoadCodeValueAndUsageMatchRegistry()
    {
        AssertRegisteredErrorCode(DoqErrorCode.ExcessiveLoad, 0x4);

        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        Assert.Contains("CloseConnectionAsync(connection, DoqErrorCode.ExcessiveLoad", server, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0031")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolErrorCodeDoesNotNormalizeAsExcessiveLoad()
    {
        Assert.NotEqual(DoqErrorCode.ExcessiveLoad, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ProtocolError));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0032")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnknownErrorCodeNormalizesToUnspecifiedError()
    {
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x100));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(-1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0032")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SpecificRegisteredCodesDoNotNormalizeAsUnspecifiedError()
    {
        Assert.NotEqual(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.NoError));
        Assert.NotEqual(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ProtocolError));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0064")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnknownOrUnexpectedErrorCodesNormalizeToUnspecifiedError()
    {
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x100));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x9999));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(-1));
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0064")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RegisteredContextualErrorCodesDoNotNormalizeAsUnspecifiedError()
    {
        Assert.Equal(DoqErrorCode.NoError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.NoError));
        Assert.Equal(DoqErrorCode.ProtocolError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ProtocolError));
        Assert.NotEqual(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.NoError));
        Assert.NotEqual(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode((long)DoqErrorCode.ProtocolError));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0033")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReservedTestErrorCodeValueAndNormalizationMatchRegistry()
    {
        AssertRegisteredErrorCode(DoqErrorCode.ErrorReserved, 0xd098ea5e);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0033")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UnknownErrorCodeDoesNotNormalizeAsReservedTestError()
    {
        Assert.NotEqual(DoqErrorCode.ErrorReserved, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x100));
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9250.json");
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqErrorCode.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ error-code tests.");
    }

    private static void AssertRegisteredErrorCode(DoqErrorCode code, long expectedValue)
    {
        Assert.Equal(expectedValue, (long)code);
        Assert.Equal(code, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(expectedValue));
    }
}
