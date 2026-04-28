using System.Collections.ObjectModel;
using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using Sigil.Windows.App.Models;
using Sigil.Windows.App.Services;

namespace Sigil.Windows.App.ViewModels;

/// <summary>
/// ViewModel for server list view.
/// Displays paired servers with pictogram preview.
/// </summary>
public sealed partial class ServerListViewModel : ObservableObject
{
    private readonly ILogger<ServerListViewModel> _logger;
    private readonly ISecureStorageService _storageService;

    [ObservableProperty]
    private ObservableCollection<ServerConfig> _servers = new();

    /// <summary>
    /// True when no servers are paired (shows empty state).
    /// </summary>
    public bool IsEmpty => Servers.Count == 0;

    public ServerListViewModel(
        ILogger<ServerListViewModel> logger,
        ISecureStorageService storageService)
    {
        _logger = logger;
        _storageService = storageService;

        LoadServers();
    }

    /// <summary>
    /// Loads all paired servers from secure storage.
    /// </summary>
    private void LoadServers()
    {
        try
        {
            var trustedServers = _storageService.GetAllTrustedServers();
            var serverConfigs = new List<ServerConfig>();

            foreach (var (fingerprint, publicKeyB64, pairedAt) in trustedServers)
            {
                try
                {
                    // Decode server public key from base64
                    var publicKey = Convert.FromBase64String(publicKeyB64);

                    // Compute fingerprint for verification
                    var computedFingerprint = Convert.ToBase64String(SHA256.HashData(publicKey));

                    if (computedFingerprint != fingerprint)
                    {
                        _logger.LogWarning(
                            "Fingerprint mismatch for server: stored={Stored}, computed={Computed}",
                            fingerprint, computedFingerprint);
                        continue;
                    }

                    // Derive pictogram from server public key for display
                    var fingerprintBytes = SHA256.HashData(publicKey);
                    var pictogram = Models.Pictogram.DeriveFromFingerprint(fingerprintBytes);

                    serverConfigs.Add(new ServerConfig
                    {
                        ServerId = fingerprint.Substring(0, 8), // First 8 chars as display ID
                        Name = $"Server {fingerprint.Substring(0, 8)}", // TODO: Store custom name during pairing
                        Url = "https://localhost", // TODO: Store URL during pairing
                        Fingerprint = fingerprint,
                        Pictogram = pictogram,
                        PairedAt = pairedAt
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to load server {Fingerprint}", fingerprint);
                }
            }

            Servers = new ObservableCollection<ServerConfig>(serverConfigs);
            OnPropertyChanged(nameof(IsEmpty));

            _logger.LogInformation("Loaded {Count} paired servers", Servers.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load servers from secure storage");
            Servers = new ObservableCollection<ServerConfig>();
            OnPropertyChanged(nameof(IsEmpty));
        }
    }

    /// <summary>
    /// Refreshes server list from storage.
    /// Called after pairing completes to update UI.
    /// </summary>
    [RelayCommand]
    public void RefreshServers()
    {
        LoadServers();
    }

    /// <summary>
    /// Opens pairing flow to add a new server.
    /// </summary>
    [RelayCommand]
    public void AddServer()
    {
        _logger.LogInformation("User requested add server");
        // TODO: Navigate to PairFlowView
        // This will be wired up when navigation service is implemented
    }
}
