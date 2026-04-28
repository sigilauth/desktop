# App Assets

This directory contains application assets for the MSIX package.

## Required Assets

The following assets are required for Windows Store submission and MSIX packaging:

### App Icon

- **Square44x44Logo.scale-100.png** — 44×44 tile icon
- **Square44x44Logo.scale-125.png** — 55×55 tile icon
- **Square44x44Logo.scale-150.png** — 66×66 tile icon
- **Square44x44Logo.scale-200.png** — 88×88 tile icon
- **Square44x44Logo.scale-400.png** — 176×176 tile icon

### Wide Tile

- **Wide310x150Logo.scale-100.png** — 310×150 wide tile
- **Wide310x150Logo.scale-125.png** — 388×188
- **Wide310x150Logo.scale-150.png** — 465×225
- **Wide310x150Logo.scale-200.png** — 620×300
- **Wide310x150Logo.scale-400.png** — 1240×600

### Splash Screen

- **SplashScreen.scale-100.png** — 620×300 splash
- **SplashScreen.scale-125.png** — 775×375
- **SplashScreen.scale-150.png** — 930×450
- **SplashScreen.scale-200.png** — 1240×600
- **SplashScreen.scale-400.png** — 2480×1200

### Store Logo

- **StoreLogo.scale-100.png** — 50×50 store badge
- **StoreLogo.scale-125.png** — 63×63
- **StoreLogo.scale-150.png** — 75×75
- **StoreLogo.scale-200.png** — 100×100
- **StoreLogo.scale-400.png** — 200×200

## Generating Assets

Use [**App Icon Generator**](https://www.appicongenerator.com/) or design in Figma/Sketch and export at multiple scales.

**Design guidelines:**
- Simple, recognizable at small sizes
- High contrast for light/dark themes
- No text in icon (use in wide tile if needed)
- Follow [Microsoft Fluent Design](https://fluent2.microsoft.design/)

## Placeholder

Currently using default WinUI 3 assets. Replace before production release.
