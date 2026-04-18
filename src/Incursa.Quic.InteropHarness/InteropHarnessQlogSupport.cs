using Incursa.Quic.Qlog;
using Incursa.Qlog;
using Incursa.Qlog.Serialization.Json;

namespace Incursa.Quic.InteropHarness;

internal sealed class InteropHarnessQlogCaptureScope : IDisposable
{
    private static readonly TimeSpan SnapshotInitialDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan SnapshotInterval = TimeSpan.FromSeconds(2);

    private readonly string outputPath;
    private readonly QuicQlogCapture capture;
    private readonly EventHandler processExitHandler;
    private readonly Timer snapshotTimer;
    private readonly object persistGate = new();
    private int disposed;

    private InteropHarnessQlogCaptureScope(string outputPath, QuicQlogCapture capture)
    {
        this.outputPath = outputPath;
        this.capture = capture;
        processExitHandler = OnProcessExit;
        AppDomain.CurrentDomain.ProcessExit += processExitHandler;
        snapshotTimer = new Timer(
            static state => ((InteropHarnessQlogCaptureScope)state!).TryPersistSnapshot(),
            this,
            SnapshotInitialDelay,
            SnapshotInterval);
    }

    public QuicQlogCapture Capture => capture;

    public string OutputPath => outputPath;

    public static InteropHarnessQlogCaptureScope? Create(InteropHarnessEnvironment settings, string fileStem)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (string.IsNullOrWhiteSpace(fileStem))
        {
            return null;
        }

        string? qlogDirectory = settings.QlogDirectory;
        if (string.IsNullOrWhiteSpace(qlogDirectory) && OperatingSystem.IsLinux())
        {
            qlogDirectory = "/logs/qlog";
        }

        if (string.IsNullOrWhiteSpace(qlogDirectory))
        {
            return null;
        }

        try
        {
            string outputPath = InteropHarnessQlogWriter.CreateOutputPath(qlogDirectory!, fileStem);
            QuicQlogCapture capture = new(title: fileStem, description: $"Captured qlog for {fileStem}.");
            return new InteropHarnessQlogCaptureScope(outputPath, capture);
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        snapshotTimer.Change(Timeout.Infinite, Timeout.Infinite);
        AppDomain.CurrentDomain.ProcessExit -= processExitHandler;
        lock (persistGate)
        {
            _ = TryPersistSnapshotCore(out _);
        }

        snapshotTimer.Dispose();
    }

    private void OnProcessExit(object? sender, EventArgs e)
    {
        _ = TryPersistSnapshot();
    }

    private bool TryPersistSnapshot()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            return true;
        }

        lock (persistGate)
        {
            if (disposed != 0)
            {
                return true;
            }

            return TryPersistSnapshotCore(out _);
        }
    }

    private bool TryPersistSnapshotCore(out string? errorMessage)
    {
        return InteropHarnessQlogWriter.TryWrite(outputPath, capture, out errorMessage);
    }
}

internal static class InteropHarnessQlogWriter
{
    private const string QlogFileExtension = ".qlog";

    public static string CreateOutputPath(string outputDirectory, string fileStem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileStem);

        string safeStem = SanitizeFileStem(fileStem);
        return Path.Combine(outputDirectory, $"{safeStem}-{Guid.NewGuid():N}{QlogFileExtension}");
    }

    public static bool TryWrite(string outputPath, QlogFile file, out string? errorMessage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentNullException.ThrowIfNull(file);

        errorMessage = null;

        if (file.Traces.Count == 0)
        {
            return true;
        }

        try
        {
            string? directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(outputPath, QlogJsonSerializer.Serialize(file, indented: true));
            return true;
        }
        catch (Exception ex)
        {
            errorMessage = $"interop harness: failed to write qlog output to '{outputPath}': {ex.Message}";
            return false;
        }
    }

    public static bool TryWrite(string outputPath, QuicQlogCapture capture, out string? errorMessage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        ArgumentNullException.ThrowIfNull(capture);

        errorMessage = null;

        if (!capture.HasTraces)
        {
            return true;
        }

        try
        {
            string? directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(outputPath, capture.ToJson(indented: true));
            return true;
        }
        catch (Exception ex)
        {
            errorMessage = $"interop harness: failed to write qlog output to '{outputPath}': {ex.Message}";
            return false;
        }
    }

    private static string SanitizeFileStem(string value)
    {
        char[] invalidFileNameChars = Path.GetInvalidFileNameChars();
        char[] sanitized = value.ToCharArray();

        for (int i = 0; i < sanitized.Length; i++)
        {
            char current = sanitized[i];
            if (current == Path.DirectorySeparatorChar ||
                current == Path.AltDirectorySeparatorChar ||
                current == ':' ||
                Array.IndexOf(invalidFileNameChars, current) >= 0)
            {
                sanitized[i] = '-';
            }
        }

        return new string(sanitized);
    }
}
