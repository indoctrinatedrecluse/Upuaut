using System.Text;
using Xunit;

namespace Upuaut.Tests;

public class HieroglyphTitleTests
{
    private static readonly string[] HieroglyphAlphabet = new[]
    {
        // 25 Uniliteral Phonetic Signs
        "𓄿", "𓇋", "𓇌", "𓂝", "𓅱", "𓃀", "𓊪", "𓆑", "𓅓", "𓈖", "𓂋", "𓉔",
        "𓎛", "𓐍", "𓄡", "𓊃", "𓋴", "𓈙", "𓈎", "𓎡", "𓎼", "𓏏", "𓍿", "𓂧", "𓆓",
        "✦",
        // Sacred Guardians of the Duat
        "𓅱", "𓊪", "𓅱", "𓄿", "𓅱", "𓏏", "✦", // Upuaut
        "𓅓", "𓂝", "𓅱", "𓅱", "𓏛", "✦", // Thoth
        "𓌳", "𓂝", "𓐍", "𓏏", "𓆄", "✦", // Ma'at
        "𓇋", "𓈖", "𓊪", "𓅱", "𓃣", "✦", // Anpu
        "𓋴", "𓈙", "𓏏", "𓏛", "✦", // Seshat
        "𓈎", "𓃀", "𓎛", "𓏏", "✦", // Kebechet
        "𓊃", "𓎡", "𓂋", "𓅓", "✦", // Seker
        // Sacred Cosmic Emblems
        "𓋹", "𓊹", "𓊽", "𓁹", "𓇳", "𓇽", "✦"
    };

    [Fact]
    public void Alphabet_ContainsValidSurrogatePairs_WithoutCorruption()
    {
        Assert.NotEmpty(HieroglyphAlphabet);

        foreach (var glyph in HieroglyphAlphabet)
        {
            if (glyph == "✦")
            {
                Assert.Single(glyph);
                continue;
            }

            // Egyptian Hieroglyphs (U+13000 to U+1342F) reside in SMP (surrogate pair: 2 chars)
            Assert.Equal(2, glyph.Length);
            Assert.True(char.IsHighSurrogate(glyph[0]), $"Expected high surrogate for glyph: {glyph}");
            Assert.True(char.IsLowSurrogate(glyph[1]), $"Expected low surrogate for glyph: {glyph}");

            int codePoint = char.ConvertToUtf32(glyph, 0);
            Assert.InRange(codePoint, 0x13000, 0x1342F);
        }
    }

    [Theory]
    [InlineData(0, 16)]
    [InlineData(10, 16)]
    [InlineData(35, 16)]
    [InlineData(50, 16)]
    public void Formatter_GeneratesValidMarqueeWindow(int offset, int windowLength)
    {
        var sb = new StringBuilder(windowLength * 3);
        for (int i = 0; i < windowLength; i++)
        {
            int idx = (offset + i) % HieroglyphAlphabet.Length;
            sb.Append(HieroglyphAlphabet[idx]).Append(' ');
        }

        var result = $"Upuaut — Opener of the Ways │ {sb.ToString().TrimEnd()}";

        Assert.StartsWith("Upuaut — Opener of the Ways │ ", result);
        Assert.DoesNotContain("??", result);
        Assert.True(result.Length > 30);
    }

    [Fact]
    public void Guardians_AreAllPresentInAlphabetStream()
    {
        var joined = string.Join(" ", HieroglyphAlphabet);

        // Check Upuaut
        Assert.Contains("𓅱 𓊪 𓅱 𓄿 𓅱 𓏏", joined);
        // Check Thoth
        Assert.Contains("𓅓 𓂝 𓅱 𓅱 𓏛", joined);
        // Check Ma'at
        Assert.Contains("𓌳 𓂝 𓐍 𓏏 𓆄", joined);
        // Check Anpu
        Assert.Contains("𓇋 𓈖 𓊪 𓅱 𓃣", joined);
        // Check Seshat
        Assert.Contains("𓋴 𓈙 𓏏 𓏛", joined);
        // Check Kebechet
        Assert.Contains("𓈎 𓃀 𓎛 𓏏", joined);
        // Check Seker
        Assert.Contains("𓊃 𓎡 𓂋 𓅓", joined);
    }
}
