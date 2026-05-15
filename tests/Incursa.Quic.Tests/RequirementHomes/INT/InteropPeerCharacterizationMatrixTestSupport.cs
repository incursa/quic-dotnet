using System.Text;

namespace Incursa.Quic.Tests;

internal sealed record InteropPeerCharacterizationEvidence(
    string ArtifactRoot,
    string LocalRole,
    string PeerSlot,
    string TestCase,
    int HelperExitCode,
    int RunnerExitCode,
    string HelperOutput,
    string RunnerStdErr);

internal sealed record InteropPeerCharacterizationRow(
    string PeerSlot,
    string LocalRole,
    string TestCase,
    string OutcomeClass,
    string FailureClass,
    string ArtifactRoot);

internal static class InteropPeerCharacterizationMatrix
{
    public static IReadOnlyList<InteropPeerCharacterizationRow> Describe(IEnumerable<InteropPeerCharacterizationEvidence> evidences)
    {
        ArgumentNullException.ThrowIfNull(evidences);

        return evidences.Select(Describe).ToArray();
    }

    public static InteropPeerCharacterizationRow Describe(InteropPeerCharacterizationEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ValidateRequiredText(evidence.ArtifactRoot, nameof(evidence.ArtifactRoot));
        ValidateRequiredText(evidence.LocalRole, nameof(evidence.LocalRole));
        ValidateRequiredText(evidence.PeerSlot, nameof(evidence.PeerSlot));
        ValidateRequiredText(evidence.TestCase, nameof(evidence.TestCase));

        return new InteropPeerCharacterizationRow(
            evidence.PeerSlot,
            evidence.LocalRole,
            evidence.TestCase,
            ClassifyOutcomeClass(evidence),
            ClassifyFailureClass(evidence),
            evidence.ArtifactRoot);
    }

    public static string RenderMarkdown(IEnumerable<InteropPeerCharacterizationRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);

        StringBuilder builder = new();
        builder.AppendLine("| peer | role | testcase | outcome | failure | artifact root |");
        builder.AppendLine("| --- | --- | --- | --- | --- | --- |");

        foreach (InteropPeerCharacterizationRow row in rows)
        {
            builder.AppendLine(
                $"| {Escape(row.PeerSlot)} | {Escape(row.LocalRole)} | {Escape(row.TestCase)} | {Escape(row.OutcomeClass)} | {Escape(row.FailureClass)} | {Escape(row.ArtifactRoot)} |");
        }

        return builder.ToString();
    }

    private static string ClassifyOutcomeClass(InteropPeerCharacterizationEvidence evidence)
    {
        string combinedText = CombineEvidenceText(evidence);
        if (evidence.HelperExitCode == 0 && evidence.RunnerExitCode == 0)
        {
            return "passed";
        }

        if (evidence.HelperExitCode == 0 && combinedText.Contains("Advisory:", StringComparison.OrdinalIgnoreCase))
        {
            return "advisory-success";
        }

        return "failed";
    }

    private static string ClassifyFailureClass(InteropPeerCharacterizationEvidence evidence)
    {
        string combinedText = CombineEvidenceText(evidence);

        if (combinedText.Contains("AckedUnsentPacket", StringComparison.OrdinalIgnoreCase) ||
            (combinedText.Contains("Largest ACKed", StringComparison.OrdinalIgnoreCase) &&
             combinedText.Contains("was never sent", StringComparison.OrdinalIgnoreCase)))
        {
            return "peer-acked-unsent-packet";
        }

        if (combinedText.Contains("zero-length destination connection ID", StringComparison.OrdinalIgnoreCase) ||
            combinedText.Contains("retired a connection ID", StringComparison.OrdinalIgnoreCase))
        {
            return "peer-zero-length-dcid-cid-retirement";
        }

        if (combinedText.Contains("Layer does not exist in packet", StringComparison.OrdinalIgnoreCase))
        {
            return "peer-packet-layer-missing";
        }

        if (combinedText.Contains("file-size mismatch", StringComparison.OrdinalIgnoreCase) ||
            combinedText.Contains("doesn't match", StringComparison.OrdinalIgnoreCase))
        {
            return "peer-transfer-size-mismatch";
        }

        if (combinedText.Contains("TLS alert 50", StringComparison.OrdinalIgnoreCase))
        {
            return "peer-tls-alert-50";
        }

        if (combinedText.Contains("Advisory:", StringComparison.OrdinalIgnoreCase) ||
            (evidence.HelperExitCode == 0 && evidence.RunnerExitCode == 0))
        {
            return "none";
        }

        return "peer-unclassified";
    }

    private static string CombineEvidenceText(InteropPeerCharacterizationEvidence evidence)
    {
        return string.Join(
            Environment.NewLine,
            evidence.HelperOutput,
            evidence.RunnerStdErr);
    }

    private static void ValidateRequiredText(string value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Peer-characterization evidence must include a non-empty value.", paramName);
        }
    }

    private static string Escape(string value)
    {
        return value.Replace("|", "\\|", StringComparison.Ordinal);
    }
}
