using Microsoft.UI.Xaml.Controls;
using Sigil.Windows.App.ViewModels;

namespace Sigil.Windows.App.Views;

/// <summary>
/// Approval view for out-of-band challenge approval.
/// Displays server info, action details, and biometric approve/deny.
/// </summary>
public sealed partial class ApprovalView : Page
{
    public ApprovalViewModel ViewModel { get; }

    public ApprovalView()
    {
        // ViewModel will be injected via DI when navigation is implemented
        // For now, create a placeholder
        ViewModel = new ApprovalViewModel(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<ApprovalViewModel>.Instance,
            new Services.SecureStorageService(
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Services.SecureStorageService>.Instance));

        this.InitializeComponent();
    }
}
