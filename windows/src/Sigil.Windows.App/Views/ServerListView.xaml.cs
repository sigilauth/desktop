using Microsoft.UI.Xaml.Controls;
using Sigil.Windows.App.ViewModels;

namespace Sigil.Windows.App.Views;

/// <summary>
/// Server list view displaying all paired servers.
/// Each server shows name and pictogram preview.
/// </summary>
public sealed partial class ServerListView : Page
{
    public ServerListViewModel ViewModel { get; }

    public ServerListView()
    {
        // ViewModel will be injected via DI when navigation is implemented
        // For now, create a placeholder
        ViewModel = new ServerListViewModel(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ServerListViewModel>.Instance,
            new Services.SecureStorageService(
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Services.SecureStorageService>.Instance));

        this.InitializeComponent();
    }
}
