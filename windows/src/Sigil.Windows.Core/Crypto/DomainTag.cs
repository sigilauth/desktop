using System.Text;

namespace Sigil.Windows.Core.Crypto;

/// <summary>
/// Domain separation tags for Sigil Auth signing operations.
/// Per api/domain-separation.md specification.
/// </summary>
public static class DomainTag
{
    /// <summary>
    /// Authentication challenge/response tag: "SIGIL-AUTH-V1\x00" (14 bytes)
    /// </summary>
    public static readonly byte[] Auth = Encoding.UTF8.GetBytes("SIGIL-AUTH-V1\0");

    /// <summary>
    /// Multi-party authorization approval tag: "SIGIL-MPA-V1\x00" (13 bytes)
    /// </summary>
    public static readonly byte[] Mpa = Encoding.UTF8.GetBytes("SIGIL-MPA-V1\0");

    /// <summary>
    /// Secure decrypt envelope tag: "SIGIL-DECRYPT-V1\x00" (17 bytes)
    /// </summary>
    public static readonly byte[] Decrypt = Encoding.UTF8.GetBytes("SIGIL-DECRYPT-V1\0");

    /// <summary>
    /// Wire protocol envelope tag: "SIGIL-CONV-V1\x00" (14 bytes)
    /// Per api/wire-protocol.md section 5.1
    /// </summary>
    public static readonly byte[] Conv = Encoding.UTF8.GetBytes("SIGIL-CONV-V1\0");

    /// <summary>
    /// Pair handshake session pictogram tag: "SIGIL-PAIR-V1\x00\x00\x00" (16 bytes, zero-padded for Argon2 salt)
    /// Per api/wire-protocol.md section 4.2
    /// </summary>
    public static readonly byte[] Pair = Encoding.UTF8.GetBytes("SIGIL-PAIR-V1\0\0\0");
}
