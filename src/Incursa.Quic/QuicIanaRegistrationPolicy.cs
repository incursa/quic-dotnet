// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicIanaRegistrationFieldKind
{
    Value,
    Status,
    Specification,
    Date,
    ChangeController,
    Contact,
    Notes,
}

internal enum QuicIanaRegistrationReviewPolicy
{
    ExpertReview,
}

internal readonly record struct QuicIanaRegistrationFieldDefinition(
    QuicIanaRegistrationFieldKind Kind,
    string Name,
    string Definition,
    bool RequiredForPermanentRegistration,
    bool RequiredForProvisionalRequest,
    bool RequiredForProvisionalRegistryEntry,
    bool OmissibleFromProvisionalRegistration);

internal static class QuicIanaRegistrationPolicy
{
    public const string Rfc8126ExpertReviewReference = "RFC8126 Section 4.5";

    private static readonly QuicIanaRegistrationFieldDefinition[] registryFields =
    [
        new(
            QuicIanaRegistrationFieldKind.Value,
            "Value",
            "The assigned codepoint.",
            RequiredForPermanentRegistration: true,
            RequiredForProvisionalRequest: true,
            RequiredForProvisionalRegistryEntry: true,
            OmissibleFromProvisionalRegistration: false),
        new(
            QuicIanaRegistrationFieldKind.Status,
            "Status",
            "\"permanent\" or \"provisional\".",
            RequiredForPermanentRegistration: true,
            RequiredForProvisionalRequest: false,
            RequiredForProvisionalRegistryEntry: true,
            OmissibleFromProvisionalRegistration: false),
        new(
            QuicIanaRegistrationFieldKind.Specification,
            "Specification",
            "A reference to a publicly available specification for the value.",
            RequiredForPermanentRegistration: true,
            RequiredForProvisionalRequest: false,
            RequiredForProvisionalRegistryEntry: false,
            OmissibleFromProvisionalRegistration: true),
        new(
            QuicIanaRegistrationFieldKind.Date,
            "Date",
            "The date of the last update to the registration.",
            RequiredForPermanentRegistration: true,
            RequiredForProvisionalRequest: false,
            RequiredForProvisionalRegistryEntry: true,
            OmissibleFromProvisionalRegistration: false),
        new(
            QuicIanaRegistrationFieldKind.ChangeController,
            "Change Controller",
            "The entity responsible for the definition of the registration.",
            RequiredForPermanentRegistration: true,
            RequiredForProvisionalRequest: false,
            RequiredForProvisionalRegistryEntry: false,
            OmissibleFromProvisionalRegistration: false),
        new(
            QuicIanaRegistrationFieldKind.Contact,
            "Contact",
            "Contact details for the registrant.",
            RequiredForPermanentRegistration: true,
            RequiredForProvisionalRequest: true,
            RequiredForProvisionalRegistryEntry: true,
            OmissibleFromProvisionalRegistration: false),
        new(
            QuicIanaRegistrationFieldKind.Notes,
            "Notes",
            "Supplementary notes about the registration.",
            RequiredForPermanentRegistration: true,
            RequiredForProvisionalRequest: false,
            RequiredForProvisionalRegistryEntry: false,
            OmissibleFromProvisionalRegistration: true),
    ];

    private static readonly QuicIanaRegistrationFieldKind[] provisionalRequestRequiredFields =
    [
        QuicIanaRegistrationFieldKind.Value,
        QuicIanaRegistrationFieldKind.Contact,
    ];

    private static readonly QuicIanaRegistrationFieldKind[] provisionalRegistryEntryRequiredFields =
    [
        QuicIanaRegistrationFieldKind.Value,
        QuicIanaRegistrationFieldKind.Status,
        QuicIanaRegistrationFieldKind.Date,
        QuicIanaRegistrationFieldKind.Contact,
    ];

    private static readonly QuicIanaRegistrationFieldKind[] provisionalOmissibleFields =
    [
        QuicIanaRegistrationFieldKind.Specification,
        QuicIanaRegistrationFieldKind.Notes,
    ];

    public static IReadOnlyList<QuicIanaRegistrationFieldDefinition> RegistryFields => registryFields;

    public static IReadOnlyList<QuicIanaRegistrationFieldKind> ProvisionalRequestRequiredFields =>
        provisionalRequestRequiredFields;

    public static IReadOnlyList<QuicIanaRegistrationFieldKind> ProvisionalRegistryEntryRequiredFields =>
        provisionalRegistryEntryRequiredFields;

    public static IReadOnlyList<QuicIanaRegistrationFieldKind> ProvisionalOmissibleFields =>
        provisionalOmissibleFields;

    public static QuicIanaRegistrationReviewPolicy ProvisionalReviewPolicy =>
        QuicIanaRegistrationReviewPolicy.ExpertReview;

    public static bool ProvisionalDateUpdateRequiresExpertReview => false;

    public static QuicIanaRegistrationFieldDefinition GetRegistryField(QuicIanaRegistrationFieldKind kind)
    {
        foreach (QuicIanaRegistrationFieldDefinition field in registryFields)
        {
            if (field.Kind == kind)
            {
                return field;
            }
        }

        throw new InvalidOperationException($"Unknown QUIC IANA registration field kind '{kind}'.");
    }

    public static bool IsValidStatusText(string value) =>
        value is "permanent" or "provisional";
}
