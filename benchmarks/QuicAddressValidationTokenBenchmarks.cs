using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks server-issued NEW_TOKEN creation and validation.
/// </summary>
[MemoryDiagnoser]
public class QuicAddressValidationTokenBenchmarks
{
    private readonly DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    private readonly DateTimeOffset validationTime = DateTimeOffset.FromUnixTimeSeconds(1_800_000_030);
    private QuicAddressValidationTokenProtector protector = null!;
    private byte[] validToken = [];
    private byte[] tamperedToken = [];
    private string remoteAddress = string.Empty;
    private string wrongRemoteAddress = string.Empty;

    /// <summary>
    /// Prepares representative token inputs and a stable listener secret.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        byte[] secret = new byte[QuicAddressValidationTokenProtector.SecretLength];
        for (int index = 0; index < secret.Length; index++)
        {
            secret[index] = unchecked((byte)(0xB0 + index));
        }

        protector = new QuicAddressValidationTokenProtector(secret, TimeSpan.FromMinutes(5));
        remoteAddress = "203.0.113.10";
        wrongRemoteAddress = "203.0.113.11";
        validToken = protector.IssueNewToken(remoteAddress, issuedAt);
        tamperedToken = validToken.ToArray();
        tamperedToken[^1] ^= 0x01;
    }

    /// <summary>
    /// Measures issuing a fresh server NEW_TOKEN.
    /// </summary>
    [Benchmark]
    public int IssueNewToken()
    {
        return protector.IssueNewToken(remoteAddress).Length;
    }

    /// <summary>
    /// Measures validating a token from the original client IP address.
    /// </summary>
    [Benchmark]
    public int ValidateNewToken()
    {
        return (int)protector.ValidateNewToken(validToken, remoteAddress, validationTime);
    }

    /// <summary>
    /// Measures rejecting a token from a changed client IP address.
    /// </summary>
    [Benchmark]
    public int ValidateNewTokenFromWrongAddress()
    {
        return (int)protector.ValidateNewToken(validToken, wrongRemoteAddress, validationTime);
    }

    /// <summary>
    /// Measures rejecting a modified token.
    /// </summary>
    [Benchmark]
    public int ValidateTamperedNewToken()
    {
        return (int)protector.ValidateNewToken(tamperedToken, remoteAddress, validationTime);
    }
}
