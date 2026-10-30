# Upuaut Windows setup

The release workflow builds a self-contained Windows x64 app and packages it with the custom WPF setup experience. Create a GitHub release by pushing a version tag such as `v1.2.0`; the workflow publishes `Upuaut-Setup-win-x64-v1.2.0.zip` to that release. Running the workflow manually creates the same package as a downloadable workflow artifact.

Extract the complete ZIP before running `Upuaut.Setup.exe`; it needs its sibling `payload` folder. Setup installs per-user under `%LOCALAPPDATA%\Programs\Upuaut` by default, creates Start Menu shortcuts for Upuaut and **Uninstall Upuaut**, copies the shared setup executable to `Uninstall.exe`, and registers the uninstaller under the current Windows account. The registry entry supports Windows Settings and Control Panel uninstall routes; running `Uninstall.exe` directly opens the same uninstall screen.

Uninstall closes Upuaut if it can exit normally and asks you to close it if it remains active. It removes files listed in the installer's manifest, its shortcuts, and its registry entry while leaving unrecognized files in a custom install folder alone. Logs and crash reports under `%LOCALAPPDATA%\Upuaut` are preserved unless you check the explicit remove-data option. The release workflow runs for new and moved `v*` tags; deleting a tag does not create a release.

## Video assets

Place the generated clips here before release:

- `installer/assets/upuaut-installer-loop.mp4` — 6-second setup background loop. The installer continues to work without it and uses its dark/gold fallback canvas.
- `src/Upuaut.App/wwwroot/media/upuaut-background.mp4` — 10-second app splash and looping canvas. The prominent **Canvas Motion** switch in the app header turns off both the video canvas and launch splash; the choice is saved for the current WebView profile.
- `src/Upuaut.App/wwwroot/media/upuaut-splash-poster.jpg` — optional still image shown while the app video loads. It can be a frame exported from the 10-second clip.

Keep both videos silent; the app clip loops continuously, so make its final frame blend into its first. The app video is darkened heavily behind the UI to preserve contrast. An absent app clip causes the app to skip its animated splash and use the normal static theme.

For Flow output, use 1920×1080, 16:9, 24 or 30 fps, H.264 MP4, no audio, and no generated text. Overlay the product title in the native UI instead of asking Flow to render lettering. The installer loops the entire clip from its media-ended event; it has no fixed-duration timer.
