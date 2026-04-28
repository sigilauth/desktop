Name:           sigilauth-desktop
Version:        0.1.0
Release:        1%{?dist}
Summary:        Hardware-backed strong authentication for Linux

License:        AGPL-3.0-or-later
URL:            https://sigilauth.com
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo rust pkgconfig meson ninja-build
BuildRequires:  gtk4-devel libadwaita-devel libsecret-devel
BuildRequires:  tpm2-tss-devel pcsc-lite-devel
BuildRequires:  desktop-file-utils libappstream-glib
Requires:       gtk4 >= 4.10 libadwaita >= 1.4 libsecret tpm2-tss pcsc-lite

%description
Sigil Auth is an open-source strong authentication system using hardware-bound
cryptographic keys. The desktop app holds its signing key in a TPM 2.0 chip or
YubiKey with the PIV applet; private keys never leave hardware.

%prep
%autosetup

%build
meson setup build --prefix=/usr --buildtype=release
meson compile -C build

%install
meson install -C build --destdir=%{buildroot}

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/org.sigilauth.Desktop.desktop
appstreamcli validate --no-net %{buildroot}%{_datadir}/metainfo/org.sigilauth.Desktop.metainfo.xml || true

%files
%license LICENSE
%{_bindir}/sigil-desktop
%{_datadir}/applications/org.sigilauth.Desktop.desktop
%{_datadir}/metainfo/org.sigilauth.Desktop.metainfo.xml
%{_datadir}/glib-2.0/schemas/org.sigilauth.Desktop.gschema.xml
%{_datadir}/icons/hicolor/*/apps/org.sigilauth.Desktop*

%post
glib-compile-schemas %{_datadir}/glib-2.0/schemas &>/dev/null || :
update-desktop-database -q %{_datadir}/applications &>/dev/null || :

%postun
glib-compile-schemas %{_datadir}/glib-2.0/schemas &>/dev/null || :
update-desktop-database -q %{_datadir}/applications &>/dev/null || :

%changelog
* Thu Apr 23 2026 Sigil Auth contributors <security@sigilauth.com> - 0.1.0-1
- Initial scaffold release.
