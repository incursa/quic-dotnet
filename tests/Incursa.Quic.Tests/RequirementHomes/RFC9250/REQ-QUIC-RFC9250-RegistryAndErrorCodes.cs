// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9250_RegistryAndErrorCodes
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0127")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RegistrySpaceUsesSixtyTwoBitQuicVariableLengthIntegerRange()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0127");

        Assert.Equal(0x3FFF_FFFF_FFFF_FFFFUL, QuicVariableLengthInteger.MaxValue);
        Assert.Contains("62-bit", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0127")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RegistrySpaceDoesNotTreatSixtyThreeBitValueAsRegisteredDoqError()
    {
        Assert.Equal(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(long.MaxValue));
        Assert.False(Enum.IsDefined(typeof(DoqErrorCode), long.MaxValue));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0128")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PermanentLowRangeRegistrationPolicyAllowsStandardsActionOrIesgApproval()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0128");

        Assert.Contains("0x00", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("0x3f", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("Standards Action", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("IESG Approval", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0128")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PermanentLowRangeRegistrationPolicyDoesNotUseExpertReviewOnly()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0128");

        Assert.DoesNotContain("Expert Review", requirement.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("Specification Required", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0129")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PermanentHighRangeRegistrationPolicyUsesSpecificationRequired()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0129");

        Assert.Contains("larger than 0x3f", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("Specification Required", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0129")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PermanentHighRangeRegistrationPolicyDoesNotUseLowRangePolicy()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0129");

        Assert.DoesNotContain("0x00 to 0x3f", requirement.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("Standards Action", requirement.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("IESG Approval", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0130")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProvisionalHighRangeRegistrationPolicyUsesExpertReview()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0130");

        Assert.Contains("Provisional", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("larger than 0x3f", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("Expert Review", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0130")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProvisionalHighRangeRegistrationPolicyDoesNotRequireStandardsAction()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0130");

        Assert.DoesNotContain("Standards Action", requirement.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("IESG Approval", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0131")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProvisionalRegistrationSpecificationCanBeOmitted()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0131");

        Assert.Contains("Specification", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("MAY be omitted", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("provisional", requirement.Statement, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0131")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProvisionalRegistrationSpecificationOptionalityIsNotPermanentPolicy()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0131");

        Assert.DoesNotContain("Permanent", requirement.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("MUST be omitted", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0132")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DescriptionCanBeSummaryWhenSpecificationReferenceExists()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0132");

        Assert.Contains("Description", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("summary", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("Specification reference is provided", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0132")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DescriptionSummaryIsNotAllowedWithoutSpecificationReference()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0132");

        Assert.DoesNotContain("if no Specification reference is provided", requirement.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("MUST be a summary", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0133")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProvisionalDateUpdatesCanSkipExpertReview()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0133");

        Assert.Contains("Date", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("provisional registration", requirement.Statement, StringComparison.Ordinal);
        Assert.Contains("without review", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0133")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProvisionalDateUpdateWaiverDoesNotApplyToPolicyChanges()
    {
        RequirementText requirement = ReadRequirement("REQ-QUIC-RFC9250-0133");

        Assert.DoesNotContain("Policy", requirement.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("Specification", requirement.Statement, StringComparison.Ordinal);
        Assert.DoesNotContain("Description", requirement.Statement, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0134")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqNoErrorUsesRegisteredValue()
    {
        AssertRegisteredErrorCode(DoqErrorCode.NoError, 0x0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0134")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqNoErrorDoesNotUseInternalErrorValue()
    {
        Assert.NotEqual(DoqErrorCode.NoError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0135")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqInternalErrorUsesRegisteredValue()
    {
        AssertRegisteredErrorCode(DoqErrorCode.InternalError, 0x1);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0135")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqInternalErrorDoesNotUseNoErrorValue()
    {
        Assert.NotEqual(DoqErrorCode.InternalError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x0));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0136")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqProtocolErrorUsesRegisteredValue()
    {
        AssertRegisteredErrorCode(DoqErrorCode.ProtocolError, 0x2);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0136")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqProtocolErrorDoesNotUseRequestCancelledValue()
    {
        Assert.NotEqual(DoqErrorCode.ProtocolError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x3));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0137")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqRequestCancelledUsesRegisteredValue()
    {
        AssertRegisteredErrorCode(DoqErrorCode.RequestCancelled, 0x3);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0137")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqRequestCancelledDoesNotUseProtocolErrorValue()
    {
        Assert.NotEqual(DoqErrorCode.RequestCancelled, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0138")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqExcessiveLoadUsesRegisteredValue()
    {
        AssertRegisteredErrorCode(DoqErrorCode.ExcessiveLoad, 0x4);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0138")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqExcessiveLoadDoesNotUseRequestCancelledValue()
    {
        Assert.NotEqual(DoqErrorCode.ExcessiveLoad, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x3));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0139")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqUnspecifiedErrorUsesRegisteredValue()
    {
        AssertRegisteredErrorCode(DoqErrorCode.UnspecifiedError, 0x5);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0139")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqUnspecifiedErrorDoesNotUseExcessiveLoadValue()
    {
        Assert.NotEqual(DoqErrorCode.UnspecifiedError, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0x4));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0140")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqErrorReservedUsesRegisteredValue()
    {
        AssertRegisteredErrorCode(DoqErrorCode.ErrorReserved, 0xd098ea5e);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9250-0140")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DoqErrorReservedDoesNotUseAdjacentValue()
    {
        Assert.NotEqual(DoqErrorCode.ErrorReserved, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(0xd098ea5d));
    }

    private static void AssertRegisteredErrorCode(DoqErrorCode code, long expectedValue)
    {
        Assert.Equal(expectedValue, (long)code);
        Assert.Equal(code, DoqErrorCodeExtensions.NormalizeReceivedErrorCode(expectedValue));
    }

    private static RequirementText ReadRequirement(string requirementId)
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        using JsonDocument document = JsonDocument.Parse(spec);
        foreach (JsonElement requirement in document.RootElement.GetProperty("requirements").EnumerateArray())
        {
            if (requirement.GetProperty("id").GetString() == requirementId)
            {
                return new RequirementText(
                    requirement.GetProperty("title").GetString() ?? string.Empty,
                    requirement.GetProperty("statement").GetString() ?? string.Empty);
            }
        }

        throw new InvalidOperationException($"Unable to locate requirement '{requirementId}'.");
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

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 registry tests.");
    }

    private readonly record struct RequirementText(string Title, string Statement);
}
