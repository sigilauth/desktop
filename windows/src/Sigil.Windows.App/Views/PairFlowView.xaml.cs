using Microsoft.UI.Xaml.Controls;
using Sigil.Windows.App.ViewModels;

namespace Sigil.Windows.App.Views;

public sealed partial class PairFlowView : Page
{
    public PairFlowViewModel ViewModel { get; }

    public PairFlowView()
    {
        ViewModel = App.GetService<PairFlowViewModel>();
        InitializeComponent();
    }
}
