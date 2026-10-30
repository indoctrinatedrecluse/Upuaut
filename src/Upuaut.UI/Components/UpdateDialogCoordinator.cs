namespace Upuaut.UI.Components;

/// <summary>Routes Help-menu update requests to the top-level floating dialog host.</summary>
public sealed class UpdateDialogCoordinator
{
    public event Action? OpenRequested;
    public void Open() => OpenRequested?.Invoke();
}
