# Windows App Scaffolding Status

**Created:** 2026-04-26 (on macOS)
**Status:** Skeleton complete, requires Windows machine for completion

---

## What's Done ✓

### 1. WinUI 3 App Project (`src/Sigil.Windows.App/`)

- [x] `.csproj` with Windows App SDK 1.7 references
- [x] `App.xaml` + `App.xaml.cs` (entry point, DI setup)
- [x] `MainWindow.xaml` + `MainWindow.xaml.cs` (basic UI: connect/disconnect, status display)
- [x] `WindowsHelloKeyProvider.cs` (stub - needs Windows Hello API implementation)
- [x] `app.manifest` (DPI awareness, Windows 10+ compatibility)
- [x] `Assets/` directory with README (icons needed)

**Features implemented:**
- Dependency injection (Microsoft.Extensions.DependencyInjection)
- WebSocket client integration (via Sigil.Windows.Core)
- Connection state UI binding
- Event subscription (ConnectionStateChanged, NotificationReceived)
- Basic notification handling (TODO: approval dialog)

### 2. MSIX Packaging Project (`src/Sigil.Windows.Package/`)

- [x] `.wapproj` packaging project
- [x] `Package.appxmanifest` with app identity
- [x] `Images/` directory for package assets

### 3. Documentation

- [x] `WINDOWS-COMPLETION.md` — step-by-step guide for Windows build
- [x] Completion checklist
- [x] Troubleshooting section
- [x] Production next steps

---

## What's Missing (Windows Machine Required)

### Critical

1. **Windows Hello implementation** — `WindowsHelloKeyProvider.cs` has stubs
   - Use `Windows.Security.Credentials.KeyCredentialManager`
   - Implement `GenerateKeypairAsync` with biometric prompt
   - Implement `SignAsync` with TPM signing

2. **App icons** — `Assets/` directory empty
   - Generate icons at required scales (44×44, 310×150, 620×300, etc.)
   - See `Assets/README.md` for full list

3. **Solution file update** — Add App and Package projects to `.sln`
   - Open in Visual Studio 2022
   - Add projects to solution
   - Set build configurations

4. **Build verification** — Cannot build WinUI 3 on macOS
   - Requires Windows SDK 10.0.22621.0+
   - Requires Windows App SDK 1.7.x runtime

### Nice-to-Have

- Approval dialog UI (for push notifications)
- Settings page (relay URL config)
- Error handling UI (connection failures, Windows Hello errors)
- Loading states / progress indicators
- Notification history / log view

---

## Next Actions

**On Windows machine:**

1. Open `Sigil.Windows.sln` in Visual Studio 2022
2. Follow `src/Sigil.Windows.App/WINDOWS-COMPLETION.md` steps 1-8
3. Implement Windows Hello provider (see step 3)
4. Add app icons (see step 4)
5. Build, test, package (steps 5-7)
6. Verify checklist (step 8)

**Estimated effort:** 2-4 hours for completion + testing

---

## Can This Be Built Now?

**On macOS:** ❌ No (WinUI 3 requires Windows SDK, Windows App SDK runtime)

**On Windows:** ⚠️ Partial
- Core library builds ✓
- Tests pass ✓
- App project scaffolded ✓
- **But:** Windows Hello stub will fail at runtime until implemented

**After Windows Hello implementation:** ✅ Yes (full build, package, deploy)

---

## Files Created

```
src/Sigil.Windows.App/
├── Sigil.Windows.App.csproj
├── App.xaml
├── App.xaml.cs
├── MainWindow.xaml
├── MainWindow.xaml.cs
├── WindowsHelloKeyProvider.cs
├── app.manifest
├── WINDOWS-COMPLETION.md
└── Assets/
    └── README.md

src/Sigil.Windows.Package/
├── Sigil.Windows.Package.wapproj
├── Package.appxmanifest
└── Images/
    └── README.md
```

Total: 13 files, ~800 lines (excluding comments/whitespace)
