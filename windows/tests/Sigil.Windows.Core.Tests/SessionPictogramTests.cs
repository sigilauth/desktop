using Sigil.Windows.Core.Crypto;
using Sigil.Windows.Core.Protocol;
using Xunit;

namespace Sigil.Windows.Core.Tests;

public sealed class SessionPictogramTests
{
    [Fact]
    public void DeriveIndices_ReturnsExpectedIndices()
    {
        var serverPub = Convert.FromHexString("02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        var clientPub = Convert.FromHexString("03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        var serverNonce = Convert.FromHexString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        var indices = SessionPictogram.DeriveIndices(serverPub, clientPub, serverNonce);

        Assert.Equal(6, indices.Length);

        foreach (var index in indices)
        {
            Assert.InRange(index, 0, 191);
        }
    }

    [Fact]
    public void DeriveIndices_IsDeterministic()
    {
        var serverPub = Convert.FromHexString("0201010101010101010101010101010101010101010101010101010101010101");
        var clientPub = Convert.FromHexString("0302020202020202020202020202020202020202020202020202020202020202");
        var serverNonce = Convert.FromHexString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        var indices1 = SessionPictogram.DeriveIndices(serverPub, clientPub, serverNonce);
        var indices2 = SessionPictogram.DeriveIndices(serverPub, clientPub, serverNonce);

        Assert.Equal(indices1, indices2);
    }

    [Fact]
    public void DeriveIndices_DifferentNonceProducesDifferentPictogram()
    {
        var serverPub = Convert.FromHexString("0201010101010101010101010101010101010101010101010101010101010101");
        var clientPub = Convert.FromHexString("0302020202020202020202020202020202020202020202020202020202020202");
        var nonce1 = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000000");
        var nonce2 = Convert.FromHexString("0000000000000000000000000000000000000000000000000000000000000001");

        var indices1 = SessionPictogram.DeriveIndices(serverPub, clientPub, nonce1);
        var indices2 = SessionPictogram.DeriveIndices(serverPub, clientPub, nonce2);

        Assert.NotEqual(indices1, indices2);
    }

    [Fact]
    public void GetEntry_ReturnsCorrectEmojiWordPairs()
    {
        var entry0 = PictogramPool.GetEntry(0);
        Assert.Equal(0, entry0.Index);
        Assert.Equal("🍎", entry0.Emoji);
        Assert.Equal("apple", entry0.Name);

        var entry191 = PictogramPool.GetEntry(191);
        Assert.Equal(191, entry191.Index);
        Assert.Equal("⛳", entry191.Emoji);
        Assert.Equal("golf", entry191.Name);
    }

    [Fact]
    public void ToSpeakable_ProducesSpaceSeparatedNames()
    {
        var entries = new[]
        {
            PictogramPool.GetEntry(0),
            PictogramPool.GetEntry(65),
            PictogramPool.GetEntry(82),
            PictogramPool.GetEntry(163),
            PictogramPool.GetEntry(129),
            PictogramPool.GetEntry(144)
        };

        var speakable = PictogramPool.ToSpeakable(entries);

        Assert.Equal("apple rocket fox anchor moon house", speakable);
    }
}
