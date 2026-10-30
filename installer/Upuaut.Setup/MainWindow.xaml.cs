using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;

namespace Upuaut.Setup;

public partial class MainWindow : Window
{
    private readonly string _payloadDirectory = Path.Combine(AppContext.BaseDirectory, "payload");
    private readonly DispatcherTimer _videoMonitor = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private readonly bool _uninstallMode;
    private Uri? _installerVideoUri;
    private TimeSpan _lastVideoPosition;
    private DateTime _lastVideoProgressUtc;
    private DateTime _lastVideoStatusUtc;
    private bool _videoOpened;
    private bool _videoProgressSeen;
    private bool _videoLoopRestartQueued;
    private int _videoRecoveryAttempts;
    private string InstallDirectory => Path.GetFullPath(InstallPathBox.Text.Trim());

    public MainWindow(bool uninstallMode = false)
    {
        InitializeComponent();
        _videoMonitor.Tick += VideoMonitor_Tick;
        Closed += (_, _) => _videoMonitor.Stop();
        Closed += (_, _) => ScheduleUpdateStagingCleanup();
        _uninstallMode = uninstallMode;
        InstallPathBox.Text = uninstallMode ? AppContext.BaseDirectory : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Upuaut");
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.6.0";
        VersionLabel.Text = $"VERSION {version}";
        if (uninstallMode)
        {
            Title = "Upuaut Uninstaller";
            InstallPanel.Visibility = Visibility.Collapsed;
            UninstallPanel.Visibility = Visibility.Visible;
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Upuaut");
            InstallPathBox.Text = key?.GetValue("InstallLocation") as string ?? AppContext.BaseDirectory;
            InstalledPathLabel.Text = InstallPathBox.Text;
        }
        else
        {
            DetectExistingInstallation();
        }
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        var mediaDirectory = Path.Combine(AppContext.BaseDirectory, "media");
        var installMediaDirectory = Path.Combine(InstallDirectory, "media");
        var posterPath = ExistingFile(mediaDirectory, installMediaDirectory, "upuaut-splash-poster.jpg");
        if (posterPath is not null)
        {
            InstallPoster.Source = new BitmapImage(new Uri(posterPath));
            InstallPoster.Visibility = Visibility.Visible;
        }

        var videoPath = ExistingFile(mediaDirectory, installMediaDirectory, "upuaut-installer-loop.mp4");
        if (videoPath is null)
        {
            StatusText.Text = posterPath is null ? "Ready when you are." : "Still artwork active · video backdrop not found.";
            CanvasPlaybackText.Text = posterPath is null ? "VIDEO MISSING · DARK CANVAS" : "STILL CANVAS · VIDEO NOT FOUND";
            CanvasPlaybackText.Visibility = Visibility.Visible;
            return;
        }

        _installerVideoUri = new Uri(Path.GetFullPath(videoPath), UriKind.Absolute);
        CanvasPlaybackText.Text = "PREPARING THE SIX-SECOND CANVAS LOOP";
        CanvasPlaybackText.Visibility = Visibility.Visible;
        InstallVideo.Source = _installerVideoUri;
    }

    private static string? ExistingFile(string firstDirectory, string secondDirectory, string filename)
    {
        var first = Path.Combine(firstDirectory, filename);
        if (File.Exists(first)) return first;
        var second = Path.Combine(secondDirectory, filename);
        return File.Exists(second) ? second : null;
    }

    private void InstallVideo_MediaOpened(object sender, RoutedEventArgs e)
    {
        _videoOpened = true;
        _videoProgressSeen = false;
        _videoLoopRestartQueued = false;
        _videoRecoveryAttempts = 0;
        _lastVideoPosition = TimeSpan.Zero;
        _lastVideoProgressUtc = DateTime.UtcNow;
        _lastVideoStatusUtc = DateTime.MinValue;
        _videoMonitor.Start();

        // Wait for WPF to finish opening/layout before starting playback. Keep the poster visible until
        // the media clock actually advances so a stalled decoder cannot masquerade as an animated canvas.
        Dispatcher.BeginInvoke(DispatcherPriority.Render, new Action(() =>
        {
            if (!_videoOpened) return;
            try
            {
                InstallVideo.Position = TimeSpan.Zero;
                InstallVideo.Play();
            }
            catch (Exception ex) { FailVideoPlayback($"Playback could not start: {ex.Message}"); }
        }));
    }

    private void InstallVideo_MediaFailed(object sender, System.Windows.ExceptionRoutedEventArgs e)
    {
        var reason = e.ErrorException?.Message;
        FailVideoPlayback(string.IsNullOrWhiteSpace(reason) ? "The media decoder could not open the video." : reason);
    }

    private void InstallVideo_MediaEnded(object sender, RoutedEventArgs e)
    {
        RestartVideoLoop();
    }

    private void VideoMonitor_Tick(object? sender, EventArgs e)
    {
        if (!_videoOpened) { _videoMonitor.Stop(); return; }

        var now = DateTime.UtcNow;
        TimeSpan position;
        try { position = InstallVideo.Position; }
        catch (Exception ex) { FailVideoPlayback($"The media clock stopped: {ex.Message}"); return; }

        if (position > _lastVideoPosition + TimeSpan.FromMilliseconds(20))
        {
            _videoProgressSeen = true;
            _lastVideoProgressUtc = now;
            _videoRecoveryAttempts = 0;
            InstallPoster.Visibility = Visibility.Collapsed;
        }

        var duration = InstallVideo.NaturalDuration.HasTimeSpan ? InstallVideo.NaturalDuration.TimeSpan : TimeSpan.Zero;
        if (duration > TimeSpan.Zero && position > TimeSpan.Zero && position >= duration - TimeSpan.FromMilliseconds(100))
        {
            RestartVideoLoop();
            _lastVideoPosition = position;
            return;
        }

        if (now - _lastVideoProgressUtc >= TimeSpan.FromSeconds(1.25))
        {
            if (_videoRecoveryAttempts >= 3)
            {
                FailVideoPlayback("The video opened but its playback clock did not advance. The still artwork is shown instead.");
                return;
            }

            _videoRecoveryAttempts++;
            _lastVideoProgressUtc = now;
            try
            {
                if (!_videoProgressSeen && InstallVideo.Position > TimeSpan.Zero) InstallVideo.Position = TimeSpan.Zero;
                InstallVideo.Play();
            }
            catch (Exception ex) { FailVideoPlayback($"Playback retry failed: {ex.Message}"); return; }
        }

        if (now - _lastVideoStatusUtc >= TimeSpan.FromSeconds(1))
        {
            var seconds = duration > TimeSpan.Zero ? duration.TotalSeconds : 6d;
            CanvasPlaybackText.Text = _videoProgressSeen
                ? $"CANVAS LOOP ACTIVE · {position.TotalSeconds:0.0} / {seconds:0.0} SEC"
                : $"STARTING CANVAS LOOP · RETRY {_videoRecoveryAttempts}/3";
            _lastVideoStatusUtc = now;
        }
        _lastVideoPosition = position;
    }

    private void RestartVideoLoop()
    {
        if (!_videoOpened || _videoLoopRestartQueued) return;
        _videoLoopRestartQueued = true;
        Dispatcher.BeginInvoke(DispatcherPriority.Render, new Action(() =>
        {
            if (!_videoOpened) { _videoLoopRestartQueued = false; return; }
            try
            {
                InstallVideo.Position = TimeSpan.Zero;
                InstallVideo.Play();
                _lastVideoPosition = TimeSpan.Zero;
                _lastVideoProgressUtc = DateTime.UtcNow;
                _videoLoopRestartQueued = false;
            }
            catch (Exception ex) { _videoLoopRestartQueued = false; FailVideoPlayback($"The loop could not restart: {ex.Message}"); }
        }));
    }

    private void FailVideoPlayback(string reason)
    {
        _videoOpened = false;
        _videoLoopRestartQueued = false;
        _videoMonitor.Stop();
        InstallPoster.Visibility = InstallPoster.Source is null ? Visibility.Collapsed : Visibility.Visible;
        CanvasPlaybackText.Text = InstallPoster.Source is null ? "VIDEO UNAVAILABLE · DARK CANVAS" : "VIDEO UNAVAILABLE · STILL CANVAS ACTIVE";
        CanvasPlaybackText.ToolTip = reason;
        Trace.WriteLine($"Upuaut setup background video failed: {reason}");
        if (StatusText is not null && InstallProgress.Visibility != Visibility.Visible && UninstallProgress.Visibility != Visibility.Visible)
            StatusText.Text = InstallPoster.Source is null ? "Video backdrop unavailable." : "Video backdrop unavailable; still artwork is active.";
    }

    private void DetectExistingInstallation()
    {
        var defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Upuaut");
        string? registryPath = null;
        string? installedVersion = null;
        var hasRegistryEntry = false;
        using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Upuaut"))
        {
            hasRegistryEntry = key is not null;
            registryPath = key?.GetValue("InstallLocation") as string;
            installedVersion = key?.GetValue("DisplayVersion") as string;
        }

        var processDirectory = Path.GetDirectoryName(Environment.ProcessPath);
        var detected = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void AddIfInstalled(string? candidate, string source)
        {
            if (string.IsNullOrWhiteSpace(candidate)) return;
            try
            {
                var fullPath = Path.GetFullPath(candidate);
                if (!IsUpuautInstallation(fullPath)) return;
                if (!detected.TryGetValue(fullPath, out var sources)) detected[fullPath] = sources = new List<string>();
                sources.Add(source);
            }
            catch { }
        }

        AddIfInstalled(registryPath, "Windows installed-apps entry");
        AddIfInstalled(defaultPath, "default install folder");
        AddIfInstalled(processDirectory, "setup launch folder");

        var selected = detected.FirstOrDefault(candidate => candidate.Value.Contains("Windows installed-apps entry"));
        if (selected.Key is null) selected = detected.FirstOrDefault(candidate => candidate.Key.Equals(defaultPath, StringComparison.OrdinalIgnoreCase));
        if (selected.Key is null) selected = detected.FirstOrDefault();

        if (selected.Key is not null)
        {
            InstallPathBox.Text = selected.Key;
            InstallButton.Content = "UPDATE UPUAUT  ›";
            var allSources = detected.SelectMany(candidate => candidate.Value).Distinct(StringComparer.OrdinalIgnoreCase);
            var sourceText = string.Join(" + ", allSources);
            ExistingInstallStatusText.Text = $"EXISTING INSTALL DETECTED · {sourceText}{(string.IsNullOrWhiteSpace(installedVersion) ? "" : $" · v{installedVersion}")}. Setup will update {selected.Key}.";
            ExistingInstallStatusText.Visibility = Visibility.Visible;
            StatusText.Text = "Existing installation found. Its files will be updated in place.";
        }
        else if (hasRegistryEntry)
        {
            ExistingInstallStatusText.Text = "A Windows uninstall entry exists, but its install files were not found. Setup will install to the default location.";
            ExistingInstallStatusText.Foreground = System.Windows.Media.Brushes.Orange;
            ExistingInstallStatusText.Visibility = Visibility.Visible;
        }
    }

    private static bool IsUpuautInstallation(string directory) =>
        Directory.Exists(directory) &&
        (File.Exists(Path.Combine(directory, "Upuaut.App.exe")) ||
         File.Exists(Path.Combine(directory, "Upuaut.install-manifest.json")) ||
         File.Exists(Path.Combine(directory, "Uninstall.exe")));

    private void Window_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not System.Windows.Controls.Button && e.LeftButton == System.Windows.Input.MouseButtonState.Pressed) DragMove();
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Choose the Upuaut installation folder", InitialDirectory = Directory.Exists(InstallPathBox.Text) ? InstallPathBox.Text : Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) };
        if (dialog.ShowDialog(this) == true) InstallPathBox.Text = dialog.FolderName;
    }

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        var target = InstallDirectory;
        if (!Directory.Exists(_payloadDirectory))
        {
            MessageBox.Show(this, "The installation package is incomplete: the payload folder is missing. Extract the full Upuaut setup archive before running Setup.exe.", "Setup package incomplete", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var files = Directory.GetFiles(_payloadDirectory, "*", SearchOption.AllDirectories);
        if (files.Length == 0)
        {
            MessageBox.Show(this, "The application payload is empty.", "Setup package incomplete", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        InstallButton.IsEnabled = false;
        InstallPathBox.IsEnabled = false;
        InstallProgress.Visibility = Visibility.Visible;
        StatusText.Text = "Preparing the destination...";
        try
        {
            foreach (var process in Process.GetProcessesByName("Upuaut.App"))
            {
                using (process)
                {
                    process.CloseMainWindow();
                    if (!process.WaitForExit(4000))
                        throw new InvalidOperationException("Upuaut is still running. Close it and select Update Upuaut again.");
                }
            }

            Directory.CreateDirectory(target);
            var installedFiles = ReadInstallManifest(target);
            for (var i = 0; i < files.Length; i++)
            {
                var source = files[i];
                var relative = Path.GetRelativePath(_payloadDirectory, source);
                var destination = Path.Combine(target, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                await using (var input = File.OpenRead(source))
                await using (var output = File.Create(destination))
                    await input.CopyToAsync(output);
                installedFiles.Add(Path.GetRelativePath(target, destination));

                InstallProgress.Value = 100d * (i + 1) / files.Length;
                StatusText.Text = $"Opening the way... {i + 1:N0} of {files.Length:N0} files";
            }

            var appExe = Path.Combine(target, "Upuaut.App.exe");
            if (!File.Exists(appExe)) throw new FileNotFoundException("The app executable is missing from the package.", appExe);
            var setupExe = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(setupExe) || !string.Equals(Path.GetFileName(setupExe), "Upuaut.Setup.exe", StringComparison.OrdinalIgnoreCase))
                setupExe = Path.Combine(AppContext.BaseDirectory, "Upuaut.Setup.exe");
            if (!File.Exists(setupExe)) throw new FileNotFoundException("The setup executable is missing; cannot install the uninstaller.", setupExe);
            var uninstallerExe = Path.Combine(target, "Uninstall.exe");
            File.Copy(setupExe, uninstallerExe, true);
            installedFiles.Add(Path.GetRelativePath(target, uninstallerExe));
            var packageVideo = Path.Combine(AppContext.BaseDirectory, "media", "upuaut-installer-loop.mp4");
            if (File.Exists(packageVideo))
            {
                var installMedia = Path.Combine(target, "media");
                Directory.CreateDirectory(installMedia);
                var installedVideo = Path.Combine(installMedia, "upuaut-installer-loop.mp4");
                File.Copy(packageVideo, installedVideo, true);
                installedFiles.Add(Path.GetRelativePath(target, installedVideo));
            }
            WriteInstallManifest(target, installedFiles);
            CreateShortcut(appExe);
            var desktopShortcut = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Upuaut.lnk");
            if (CreateDesktopShortcutCheckBox.IsChecked == true)
                CreateShortcut(appExe, desktopShortcut: true);
            else if (File.Exists(desktopShortcut))
                File.Delete(desktopShortcut);
            CreateShortcut(uninstallerExe, "Uninstall Upuaut", "--uninstall");
            WriteUninstaller(target, uninstallerExe);
            StatusText.Text = "Upuaut is ready. The path is open.";
            InstallButton.Content = "LAUNCH UPUAUT  ›";
            InstallButton.IsEnabled = true;
            InstallButton.Click -= Install_Click;
            InstallButton.Click += Launch_Click;
        }
        catch (Exception ex)
        {
            StatusText.Text = "Installation could not be completed.";
            MessageBox.Show(this, ex.Message, "Upuaut setup failed", MessageBoxButton.OK, MessageBoxImage.Error);
            InstallButton.IsEnabled = true;
            InstallPathBox.IsEnabled = true;
        }
    }

    private static void CreateShortcut(string executable, string shortcutName = "Upuaut", string arguments = "", bool desktopShortcut = false)
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("Windows Script Host is unavailable; could not create the Start Menu shortcut.");
        dynamic shell = Activator.CreateInstance(shellType)!;
        var shortcutDirectory = desktopShortcut
            ? Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs");
        var shortcutPath = Path.Combine(shortcutDirectory, $"{shortcutName}.lnk");
        Directory.CreateDirectory(Path.GetDirectoryName(shortcutPath)!);
        dynamic shortcut = shell.CreateShortcut(shortcutPath);
        shortcut.TargetPath = executable;
        shortcut.Arguments = arguments;
        shortcut.WorkingDirectory = Path.GetDirectoryName(executable);
        shortcut.IconLocation = executable;
        shortcut.Description = shortcutName == "Upuaut" ? "Upuaut — Opener of the Ways" : "Uninstall Upuaut";
        shortcut.Save();
    }

    private static void WriteUninstaller(string target, string uninstallerExe)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\Upuaut");
        key.SetValue("DisplayName", "Upuaut — Opener of the Ways");
        key.SetValue("DisplayVersion", Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.6.0");
        key.SetValue("Publisher", "Upuaut Project");
        key.SetValue("InstallLocation", target);
        key.SetValue("DisplayIcon", Path.Combine(target, "Upuaut.App.exe"));
        key.SetValue("UninstallString", $"\"{uninstallerExe}\" --uninstall");
        key.SetValue("URLInfoAbout", "https://github.com/indoctrinatedrecluse/Upuaut");
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
    }

    private static HashSet<string> ReadInstallManifest(string target)
    {
        var manifestPath = Path.Combine(target, "Upuaut.install-manifest.json");
        try
        {
            return File.Exists(manifestPath)
                ? System.Text.Json.JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(manifestPath)) ?? new(StringComparer.OrdinalIgnoreCase)
                : new(StringComparer.OrdinalIgnoreCase);
        }
        catch { return new(StringComparer.OrdinalIgnoreCase); }
    }

    private static void WriteInstallManifest(string target, HashSet<string> files)
    {
        File.WriteAllText(Path.Combine(target, "Upuaut.install-manifest.json"),
            System.Text.Json.JsonSerializer.Serialize(files.Order(StringComparer.OrdinalIgnoreCase), new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }

    private async void Uninstall_Click(object sender, RoutedEventArgs e)
    {
        UninstallButton.IsEnabled = false;
        RemoveUserDataCheckBox.IsEnabled = false;
        UninstallProgress.Visibility = Visibility.Visible;
        UninstallStatusText.Text = "Checking for active Upuaut sessions...";
        try
        {
            foreach (var process in Process.GetProcessesByName("Upuaut.App"))
            {
                using (process)
                {
                    process.CloseMainWindow();
                    if (!process.WaitForExit(4000))
                        throw new InvalidOperationException("Upuaut is still running. Close it and select Remove Upuaut again.");
                }
            }

            UninstallProgress.Value = 45;
            UninstallStatusText.Text = "Preparing complete removal...";
            var cleanupScript = CreateCleanupScript(InstallDirectory, RemoveUserDataCheckBox.IsChecked == true);
            var start = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-ExecutionPolicy");
            start.ArgumentList.Add("Bypass");
            start.ArgumentList.Add("-File");
            start.ArgumentList.Add(cleanupScript);
            using var cleanupProcess = Process.Start(start);
            if (cleanupProcess is null) throw new InvalidOperationException("Could not launch Windows cleanup.");
            UninstallProgress.Value = 100;
            UninstallStatusText.Text = "Cleanup started. This window will close.";
            await Task.Delay(450);
            Close();
        }
        catch (Exception ex)
        {
            UninstallStatusText.Text = "Removal was not completed.";
            MessageBox.Show(this, ex.Message, "Upuaut uninstall", MessageBoxButton.OK, MessageBoxImage.Warning);
            UninstallButton.IsEnabled = true;
            RemoveUserDataCheckBox.IsEnabled = true;
        }
    }

    private static string CreateCleanupScript(string installDirectory, bool removeUserData)
    {
        var startMenu = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs");
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var data = System.Text.Json.JsonSerializer.Serialize(new { installDirectory, startMenu, desktop, localAppData, removeUserData });
        var encoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(data));
        var script = Path.Combine(Path.GetTempPath(), $"Upuaut-Uninstall-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(script, $$"""
            $ErrorActionPreference = 'Continue'
            $data = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{{encoded}}')) | ConvertFrom-Json
            Start-Sleep -Seconds 2
            $startMenu = [System.IO.Path]::GetFullPath($data.startMenu)
            Remove-Item -LiteralPath (Join-Path $startMenu 'Upuaut.lnk') -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $startMenu 'Uninstall Upuaut.lnk') -Force -ErrorAction SilentlyContinue
            $desktop = [System.IO.Path]::GetFullPath($data.desktop)
            Remove-Item -LiteralPath (Join-Path $desktop 'Upuaut.lnk') -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Upuaut' -Recurse -Force -ErrorAction SilentlyContinue
            $install = [System.IO.Path]::GetFullPath($data.installDirectory)
            $manifestPath = Join-Path $install 'Upuaut.install-manifest.json'
            $ownedDirectories = @{}
            if (Test-Path -LiteralPath $manifestPath) {
                $rootPrefix = $install.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
                $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
                foreach ($relative in $manifest) {
                    if ([System.IO.Path]::IsPathRooted([string]$relative)) { continue }
                    $candidate = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($install, [string]$relative))
                    if ($candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
                        $parent = [System.IO.Path]::GetDirectoryName($candidate)
                        while ($parent -and $parent.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and $parent -ne $install) {
                            $ownedDirectories[$parent] = $true
                            $parent = [System.IO.Path]::GetDirectoryName($parent)
                        }
                    }
                }
            }
            Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
            foreach ($directory in ($ownedDirectories.Keys | Sort-Object { $_.Length } -Descending)) {
                if (Test-Path -LiteralPath $directory -PathType Container) {
                    if (-not (Get-ChildItem -LiteralPath $directory -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $directory -Force -ErrorAction SilentlyContinue }
                }
            }
            if ((Test-Path -LiteralPath $install -PathType Container) -and $install -ne [System.IO.Path]::GetPathRoot($install)) {
                if (-not (Get-ChildItem -LiteralPath $install -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $install -Force -ErrorAction SilentlyContinue }
            }
            if ($data.removeUserData) {
                $appData = Join-Path $data.localAppData 'Upuaut'
                Remove-Item -LiteralPath (Join-Path $appData 'Logs') -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath (Join-Path $appData 'Crashes') -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path $appData) {
                    $remaining = Get-ChildItem -LiteralPath $appData -Force -ErrorAction SilentlyContinue
                    if (-not $remaining) { Remove-Item -LiteralPath $appData -Force -ErrorAction SilentlyContinue }
                }
            }
            Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
            """, System.Text.Encoding.UTF8);
        return script;
    }

    private void Launch_Click(object sender, RoutedEventArgs e)
    {
        var executable = Path.Combine(Path.GetFullPath(InstallPathBox.Text.Trim()), "Upuaut.App.exe");
        Process.Start(new ProcessStartInfo(executable) { WorkingDirectory = Path.GetDirectoryName(executable)! });
        Close();
    }

    private void CancelUninstall_Click(object sender, RoutedEventArgs e) => Close();

    private static void ScheduleUpdateStagingCleanup()
    {
        try
        {
            var updatesRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "Upuaut", "Updates")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var currentDirectory = Path.GetFullPath(AppContext.BaseDirectory);
            if (!currentDirectory.StartsWith(updatesRoot, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(new DirectoryInfo(currentDirectory).Name, "package", StringComparison.OrdinalIgnoreCase))
                return;

            var stagingDirectory = Directory.GetParent(currentDirectory)?.FullName;
            if (stagingDirectory is null ||
                !string.Equals(Directory.GetParent(stagingDirectory)?.FullName?.TrimEnd(Path.DirectorySeparatorChar), updatesRoot.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) ||
                !Guid.TryParse(Path.GetFileName(stagingDirectory), out _))
                return;

            var scriptPath = Path.Combine(Path.GetTempPath(), $"Upuaut-Update-Cleanup-{Guid.NewGuid():N}.ps1");
            var safeDirectory = stagingDirectory.Replace("'", "''");
            File.WriteAllText(scriptPath, $$"""
                $setupPid = {{Environment.ProcessId}}
                $stagingDirectory = '{{safeDirectory}}'
                while (Get-Process -Id $setupPid -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 750 }
                Remove-Item -LiteralPath $stagingDirectory -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
                """, System.Text.Encoding.UTF8);
            var start = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-ExecutionPolicy");
            start.ArgumentList.Add("Bypass");
            start.ArgumentList.Add("-File");
            start.ArgumentList.Add(scriptPath);
            Process.Start(start);
        }
        catch { /* Staging cleanup is best-effort; an update must not be held up by temp cleanup. */ }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
