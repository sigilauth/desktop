namespace Sigil.Windows.Core.Abstractions;

/// <summary>
/// Minimal device key provider interface for WebSocket authentication.
/// Full implementation lives in Sigil.Windows.Platform (Windows-only).
/// </summary>
public interface IDeviceKeyProvider
{
    Task<DeviceKeyHandle> GenerateKeypairAsync(CancellationToken cancellationToken = default);

    Task<byte[]> SignAsync(
        DeviceKeyHandle handle,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken = default);
}
