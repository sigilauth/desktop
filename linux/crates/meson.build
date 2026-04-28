cargo_options = ['--manifest-path', meson.project_source_root() / 'Cargo.toml']
cargo_options += ['--target-dir', meson.project_build_root() / 'target']

if get_option('buildtype') == 'release'
  cargo_options += ['--release']
  rust_target = 'release'
else
  rust_target = 'debug'
endif

cargo_env = environment()
cargo_env.set('CARGO_HOME', meson.project_build_root() / 'cargo-home')

custom_target(
  'sigil-desktop',
  output: 'sigil-desktop',
  install: true,
  install_dir: bindir,
  console: true,
  build_by_default: true,
  command: [
    cargo, 'build',
    cargo_options,
    '--package', 'sigil-desktop',
    '&&',
    'cp',
    meson.project_build_root() / 'target' / rust_target / 'sigil-desktop',
    '@OUTPUT@',
  ],
)
