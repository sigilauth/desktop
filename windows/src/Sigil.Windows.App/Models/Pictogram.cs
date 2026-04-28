using Sigil.Windows.Core.Protocol;

namespace Sigil.Windows.App.Models;

/// <summary>
/// Pictogram representation for UI display.
/// Wraps PictogramEntry[] for data binding in XAML.
/// </summary>
public sealed class Pictogram
{
    /// <summary>
    /// Pictogram entries (6 emoji+name pairs).
    /// </summary>
    public required PictogramEntry[] Entries { get; init; }

    /// <summary>
    /// Speakable representation (space-separated names).
    /// Example: "apple rocket fox anchor moon house"
    /// </summary>
    public required string Speakable { get; init; }

    /// <summary>
    /// Creates Pictogram from derived indices.
    /// </summary>
    public static Pictogram FromIndices(int[] indices)
    {
        var entries = PictogramPool.GetEntries(indices);
        var speakable = PictogramPool.ToSpeakable(entries);

        return new Pictogram
        {
            Entries = entries,
            Speakable = speakable
        };
    }

    /// <summary>
    /// Derives Pictogram from server fingerprint for display in server list.
    /// Uses first 32 bytes of fingerprint as pseudo-nonce (deterministic).
    /// </summary>
    public static Pictogram DeriveFromFingerprint(byte[] fingerprint)
    {
        if (fingerprint.Length < 32)
        {
            throw new ArgumentException("Fingerprint must be at least 32 bytes", nameof(fingerprint));
        }

        // For server list display, we derive a stable pictogram from the fingerprint alone
        // This is simpler than storing pictogram data separately
        // Uses fingerprint as both server_pub and nonce (deterministic)
        var pseudo = new byte[33];
        pseudo[0] = 0x02; // Compressed public key prefix
        Array.Copy(fingerprint, 0, pseudo, 1, 32);

        var indices = Sigil.Windows.Core.Crypto.SessionPictogram.DeriveIndices(
            pseudo, pseudo, fingerprint.AsSpan(0, 32));

        return FromIndices(indices);
    }
}
