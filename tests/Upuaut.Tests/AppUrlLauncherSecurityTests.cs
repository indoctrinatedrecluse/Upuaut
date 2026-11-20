using Upuaut.Core.Diagnostics;

namespace Upuaut.Tests;

public class AppUrlLauncherSecurityTests
{
    [Theory]
    [InlineData("file:///C:/Windows/System32/calc.exe")]
    [InlineData("cmd:///C/calc.exe")]
    [InlineData("powershell://invoke-expression")]
    [InlineData("javascript:alert(1)")]
    [InlineData("data:text/html,<script>alert(1)</script>")]
    [InlineData("ms-msdt:/id PCWDiagnostic")]
    [InlineData("C:\\Windows\\System32\\cmd.exe")]
    [InlineData("../../../relative/path")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void TryLaunchWebUrl_RejectsNonWebSchemesAndPayloads(string? maliciousUrl)
    {
        var result = AppUrlLauncher.TryLaunchWebUrl(maliciousUrl);
        Assert.False(result);
    }
}
