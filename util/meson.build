if get_option('install_udev_rules')
  udev = dependency('udev')

  install_data([
      '50-flashprog.rules'
    ],
    install_dir : join_paths(udev.get_variable(pkgconfig : 'udevdir'), 'rules.d')
  )
endif
