project('mknk-bios-update', 'c', version: '0.1.0', meson_version: '>=0.63',
        default_options: ['c_std=c17', 'warning_level=2'])

gtk = dependency('gtk4', version: '>=4.8')
deps = [gtk, dependency('gio-unix-2.0'), dependency('json-glib-1.0')]
executable('mknk-bios-update', 'src/main.c', 'src/session.c', dependencies: deps, install: true)

backend_dir = 'lib/mknk-bios-update'
install_data('backend/catalog.py', 'backend/engine.py', 'backend/firmware_api.py', 'backend/hardware.py',
             'backend/journal.py', 'backend/platform_linux.py', 'backend/service.py', 'backend/worker.py',
             install_dir: backend_dir)
install_data('mknk-bios-update-design-and-sample/mknk-bios-update.py', rename: 'firmware.py', install_dir: backend_dir)
install_data('data/io.github.mknk.BiosUpdate.desktop', install_dir: get_option('datadir') / 'applications')
install_data('data/io.github.mknk.BiosUpdate1.xml', install_dir: get_option('datadir') / 'dbus-1/interfaces')
install_data('data/io.github.mknk.BiosUpdate1.conf', install_dir: get_option('datadir') / 'dbus-1/system.d')
install_data('data/io.github.mknk.BiosUpdate1.service', install_dir: get_option('datadir') / 'dbus-1/system-services')
install_data('data/mknk-bios-update.service', install_dir: 'lib/systemd/system')
install_data('data/mknk-bios-update.sysusers', rename: 'mknk-bios-update.conf', install_dir: 'lib/sysusers.d')
install_data('data/mknk-bios-update-login.desktop', install_dir: get_option('sysconfdir') / 'xdg/autostart')
docdir = get_option('datadir') / 'doc' / meson.project_name()
install_data('README.md', install_dir: docdir)
install_data('docs/superpowers/specs/2026-11-21-linux-bios-updater-design.md',
             install_dir: docdir / 'docs/superpowers/specs')
install_data('mknk-bios-update-design-and-sample/Linux-BIOS-Updater-Design.md',
             install_dir: docdir / 'mknk-bios-update-design-and-sample')

python = find_program('python3')
test('controller and firmware observations', python,
     args: ['-B', '-m', 'unittest', 'discover', '-s', meson.project_source_root() / 'tests'], timeout: 180)
test('existing CLI', python, args: ['-B', '-m', 'unittest', 'discover', '-s',
     meson.project_source_root() / 'mknk-bios-update-design-and-sample'], timeout: 180)
ui_tests = executable('ui-acceptance', 'tests/ui_acceptance.c', 'src/session.c', dependencies: deps)
xvfb = find_program('xvfb-run', required: false)
if xvfb.found()
  test('GTK single-window flow on isolated D-Bus', xvfb, args: ['-a', ui_tests],
       env: ['GSK_RENDERER=cairo', 'GTK_A11Y=none', 'GSETTINGS_BACKEND=memory'], timeout: 180)
endif
