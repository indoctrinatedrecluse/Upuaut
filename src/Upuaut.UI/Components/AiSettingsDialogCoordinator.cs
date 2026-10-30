namespace Upuaut.UI.Components;

/// <summary>Opens the shared AI settings surface from any workspace or menu.</summary>
public sealed class AiSettingsDialogCoordinator
{
    public event Action? OpenRequested;
    public event Action? ConfigurationChanged;
    public void Open() => OpenRequested?.Invoke();
    public void NotifyConfigurationChanged() => ConfigurationChanged?.Invoke();
}
