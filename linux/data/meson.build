desktop_conf = configuration_data()
desktop_conf.set('app_id', app_id)

desktop_file = configure_file(
  input: '@0@.desktop.in'.format(app_id),
  output: '@0@.desktop'.format(app_id),
  configuration: desktop_conf,
)

desktop_validate = find_program('desktop-file-validate', required: false)
if desktop_validate.found()
  test('validate-desktop-file', desktop_validate, args: [desktop_file])
endif

install_data(desktop_file, install_dir: datadir / 'applications')

metainfo_conf = configuration_data()
metainfo_conf.set('app_id', app_id)

metainfo_file = configure_file(
  input: '@0@.metainfo.xml.in'.format(app_id),
  output: '@0@.metainfo.xml'.format(app_id),
  configuration: metainfo_conf,
)

appstream_validate = find_program('appstreamcli', required: false)
if appstream_validate.found()
  test('validate-metainfo', appstream_validate,
       args: ['validate', '--no-net', metainfo_file])
endif

install_data(metainfo_file, install_dir: datadir / 'metainfo')

gschema_conf = configuration_data()
gschema_conf.set('app_id', app_id)
gschema_conf.set('gettext_package', gettext_package)

gschema_file = configure_file(
  input: '@0@.gschema.xml.in'.format(app_id),
  output: '@0@.gschema.xml'.format(app_id),
  configuration: gschema_conf,
)

install_data(gschema_file, install_dir: datadir / 'glib-2.0' / 'schemas')

install_subdir('icons', install_dir: datadir)
