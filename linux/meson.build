project(
  'sigilauth-desktop',
  'rust',
  version: '0.1.0',
  license: 'AGPL-3.0-or-later',
  meson_version: '>= 0.59.0',
  default_options: ['warning_level=2'],
)

app_id = 'org.sigilauth.Desktop'
gettext_package = meson.project_name()

prefix = get_option('prefix')
bindir = get_option('bindir')
datadir = get_option('datadir')
localedir = get_option('localedir')

dependency('gtk4', version: '>= 4.10')
dependency('libadwaita-1', version: '>= 1.4')
dependency('libsecret-1', version: '>= 0.20')
# tss-esapi + yubikey linked via Cargo at build time

cargo = find_program('cargo', required: true)
rustc = find_program('rustc', required: true)

subdir('data')
subdir('po')
subdir('crates')

gnome = import('gnome')
gnome.post_install(
  glib_compile_schemas: true,
  gtk_update_icon_cache: true,
  update_desktop_database: true,
)
