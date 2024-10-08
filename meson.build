project('flashprogutils', 'c',
  version : run_command('util/getversion.sh', '--version', check : true).stdout().strip(),
  license : 'GPL-2.0',
  meson_version : '>=0.53.0',
  default_options : [
    'warning_level=2',
    'c_std=c99',
    'werror=true',
    'optimization=s',
    'debug=false',
  ],
)

# libtool versioning
lt_current = '1'
lt_revision = '0'
lt_age = '0'
lt_version = '@0@.@1@.@2@'.format(lt_current, lt_age, lt_revision)

# hide/enable some warnings
warning_flags = [
  '-Wshadow',
  '-Wmissing-prototypes',
  '-Wwrite-strings',
  '-Wno-unused-parameter',
  '-Wno-address-of-packed-member',
  '-Wno-enum-conversion',
  '-Wno-missing-braces',
]

cc = meson.get_compiler('c')
add_project_arguments(cc.get_supported_arguments(warning_flags), language : 'c')
add_project_arguments('-D_DEFAULT_SOURCE', language : 'c')
add_project_arguments('-D_POSIX_C_SOURCE=200809L', language : 'c') # required for fileno, nanosleep, and strndup
add_project_arguments('-D_BSD_SOURCE', language : 'c') # required for glibc < v2.19
add_project_arguments('-D__BSD_VISIBLE', language : 'c') # required for u_char, u_int, u_long on FreeBSD
add_project_arguments('-D__XSI_VISIBLE', language : 'c') # required for gettimeofday() on FreeBSD
add_project_arguments('-D_NETBSD_SOURCE', language : 'c') # required for indirect include of strings.h on NetBSD
add_project_arguments('-D_DARWIN_C_SOURCE', language : 'c') # required for indirect include of strings.h on MacOS
add_project_arguments('-DFLASHPROG_VERSION="' + meson.project_version() + '"', language : 'c')

# get defaults from configure
config_print_wiki = get_option('classic_cli_print_wiki')
config_default_programmer_name = get_option('default_programmer_name')
config_default_programmer_args = get_option('default_programmer_args')

cargs = []
deps = []
srcs = files(
  '82802ab.c',
  'at45db.c',
  'bitbang_spi.c',
  'edi.c',
  'en29lv640b.c',
  'flashchips.c',
  'flashprog.c',
  'fmap.c',
  'helpers.c',
  'helpers_fileio.c',
  'ich_descriptors.c',
  'jedec.c',
  'layout.c',
  'libflashprog.c',
  'memory_bus.c',
  'opaque.c',
  'parallel.c',
  'print.c',
  'programmer.c',
  'programmer_table.c',
  'sfdp.c',
  'spi25.c',
  'spi25_prepare.c',
  'spi25_statusreg.c',
  'spi95.c',
  'spi.c',
  'sst28sf040.c',
  'sst49lfxxxc.c',
  'sst_fwhub.c',
  'stm50.c',
  'udelay.c',
  'w29ee011.c',
  'w39.c',
  'writeprotect.c',
  'writeprotect_ranges.c',
)

# check for required symbols
if cc.has_function('clock_gettime')
  add_project_arguments('-DHAVE_CLOCK_GETTIME=1', language : 'c')
endif
if cc.has_function('strnlen')
  add_project_arguments('-DHAVE_STRNLEN=1', language : 'c')
endif
if cc.check_header('sys/utsname.h')
  add_project_arguments('-DHAVE_UTSNAME=1', language : 'c')
endif
if host_machine.system() in ['cygwin', 'windows']
  add_project_arguments('-DIS_WINDOWS=1', language : 'c')
else
  add_project_arguments('-DIS_WINDOWS=0', language : 'c')
endif

if host_machine.system() == 'linux'
  custom_baud_c = 'custom_baud_linux.c'
elif host_machine.system() == 'darwin'
  custom_baud_c = 'custom_baud_darwin.c'
else
  custom_baud_c = 'custom_baud.c'
endif

systems_hwaccess   = [ 'linux', 'openbsd', 'freebsd', 'dragonfly', 'netbsd' ]
systems_serial     = [ 'linux', 'openbsd', 'freebsd', 'dragonfly', 'netbsd', 'darwin' ]

cpus_port_io = [ 'x86', 'x86_64' ]
cpus_raw_mem = [ 'x86', 'x86_64', 'mips', 'mips64', 'ppc', 'ppc64', 'arm', 'aarch64', 'sparc', 'sparc64', 'arc', 'e2k' ]

group_ftdi   = get_option('programmer').contains('group_ftdi')
group_pci    = get_option('programmer').contains('group_pci')
group_usb    = get_option('programmer').contains('group_usb')
group_i2c    = get_option('programmer').contains('group_i2c')
group_serial = get_option('programmer').contains('group_serial')
group_jlink  = get_option('programmer').contains('group_jlink')
group_gpiod  = get_option('programmer').contains('group_gpiod')
group_internal = get_option('programmer').contains('group_internal')
group_external = get_option('programmer').contains('group_external')

libpci     = dependency('libpci', required : group_pci, static : (host_machine.system() == 'openbsd' ? true : false)) # On openbsd a static version of libpci is needed to get also -libz
libusb1    = dependency('libusb-1.0', required : group_usb)
libftdi1   = dependency('libftdi1', required : group_ftdi)
libjaylink = dependency('libjaylink', required : group_jlink)
libgpiod   = dependency('libgpiod', required : group_gpiod)

subdir('platform')

if systems_hwaccess.contains(host_machine.system())
  srcs += files('hwaccess_physmap.c')
  if ['x86', 'x86_64'].contains(host_machine.cpu_family())
    srcs += files('hwaccess_x86_msr.c', 'hwaccess_x86_io.c')
  endif
endif

# Pseudo dependencies
linux_headers = \
  cc.has_header('linux/i2c.h')     and \
  cc.has_header('linux/i2c-dev.h') and \
  cc.has_header('mtd/mtd-user.h')  and \
  cc.has_header('linux/spi/spidev.h') ? declare_dependency() : dependency('', required : false)

# '<programmer_name>' : {
#   'system'      : list[string],  # default: ['all']
#   'cpu_families : list[string],  # default: ['all']
#   'deps'        : list[dep],     # default: []
#   'groups       : list[boolean], # default: []
#   'srcs'        : list[file],    # default: []
#   'flags'       : list[string],  # default: []
#   'default'     : boolean,       # default: true
#   'active'      : boolean,       # added on runtime
# }
programmer = {
  'atahpt' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_port_io ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('atahpt.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_ATAHPT=1' ],
    'default' : false, # not yet working
  },
  'atapromise' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_port_io, cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('atapromise.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_ATAPROMISE=1' ],
    'default' : false,
  },
  'atavia' : {
    'systems' : systems_hwaccess,
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('atavia.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_ATAVIA=1' ],
  },
  'buspirate_spi' : {
    'systems' : systems_serial,
    'groups'  : [ group_serial, group_external ],
    'srcs'    : files('buspirate_spi.c', 'serial.c', custom_baud_c),
    'flags'   : [ '-DCONFIG_BUSPIRATE_SPI=1' ],
  },
  'ch341a_spi' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_external ],
    'srcs'    : files('ch341a_spi.c'),
    'flags'   : [ '-DCONFIG_CH341A_SPI=1' ],
  },
  'ch347_spi' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_external ],
    'srcs'    : files('ch347_spi.c'),
    'flags'   : [ '-DCONFIG_CH347_SPI=1' ],
  },
  'dediprog' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_external ],
    'srcs'    : files('dediprog.c', 'usbdev.c'),
    'flags'   : [ '-DCONFIG_DEDIPROG=1' ],
  },
  'developerbox_spi' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_external ],
    'srcs'    : files('developerbox_spi.c', 'usbdev.c'),
    'flags'   : [ '-DCONFIG_DEVELOPERBOX_SPI=1' ],
  },
  'digilent_spi' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_external ],
    'srcs'    : files('digilent_spi.c'),
    'flags'   : [ '-DCONFIG_DIGILENT_SPI=1' ],
  },
  'dirtyjtag_spi' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_external ],
    'srcs'    : files('dirtyjtag_spi.c'),
    'flags'   : [ '-DCONFIG_DIRTYJTAG_SPI=1' ],
  },
  'drkaiser' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('drkaiser.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_DRKAISER=1' ],
  },
  'dummy'     : {
    'srcs'    : files('dummyflasher.c'),
    'flags'   : [ '-DCONFIG_DUMMY=1' ],
  },
  'ft2232_spi' : {
    'deps'    : [ libftdi1 ],
    'groups'  : [ group_ftdi, group_external ],
    'srcs'    : files('ft2232_spi.c' ),
    'flags'   : [ '-DCONFIG_FT2232_SPI=1' ],
  },
  'ft4222_spi' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_ftdi, group_external ],
    'srcs'    : files('ft4222_spi.c' ),
    'flags'   : [ '-DCONFIG_FT4222_SPI=1' ],
  },
  'gfxnvidia' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('gfxnvidia.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_GFXNVIDIA=1' ],
  },
  'internal' : {
    'systems' : systems_hwaccess + ['linux'],
    'cpu_families' : (host_machine.system() == 'linux' ? [ cpus_raw_mem ] : [ ['x86', 'x86_64'] ]),
    'deps'    : [ libpci ],
    'groups'  : [ group_internal ],
    'srcs'    : (host_machine.cpu_family() in ['x86', 'x86_64'] ? files(
      'processor_enable.c',
      'chipset_enable.c',
      'board_enable.c',
      'cbtable.c',
      'internal.c',
      'it87spi.c',
      'sb600spi.c',
      'amd_imc.c',
      'amd_spi100.c',
      'wbsio_spi.c',
      'mcp6x_spi.c',
      'ichspi.c',
      'dmi.c',
      'pcidev.c',
      'known_boards.c',
    ) : files(
      'board_enable.c',
      'cbtable.c',
      'chipset_enable.c',
      'internal.c',
      'processor_enable.c',
      'pcidev.c',
      'known_boards.c',
    )),
    'flags' : [
      '-DCONFIG_INTERNAL=1',
      '-DCONFIG_INTERNAL_DMI=' + (get_option('use_internal_dmi') ? '1' : '0'),
      '-DLINUX_MTD_AS_INTERNAL=' + (host_machine.cpu_family() in ['x86', 'x86_64'] ? '0' : '1'),
    ]
  },
  'it8212' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('it8212.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_IT8212=1' ],
  },
  'jlink_spi' : {
    'deps'    : [ libjaylink ],
    'groups'  : [ group_jlink, group_external ],
    'srcs'    : files('jlink_spi.c'),
    'flags'   : [ '-DCONFIG_JLINK_SPI=1' ],
  },
  'linux_gpio_spi' : {
    'systems' : [ 'linux' ],
    'deps'    : [ libgpiod ],
    'groups'  : [ group_gpiod, group_external ],
    'srcs'    : libgpiod.version() < '2.0.0'
                  ? files('linux_gpio_spi.c')
                  : files('linux_gpio2_spi.c'),
    'flags'   : [ '-DCONFIG_LINUX_GPIO_SPI=1' ],
  },
  'linux_mtd' : {
    'systems' : [ 'linux' ],
    'deps'    : [ linux_headers ],
    'groups'  : [ group_internal ],
    'srcs'    : files('linux_mtd.c'),
    'flags'   : [ '-DCONFIG_LINUX_MTD=1' ],
  },
  'linux_spi' : {
    'systems' : [ 'linux' ],
    'deps'    : [ linux_headers ],
              # internal / external?
    'srcs'    : files('linux_spi.c'),
    'flags'   : [ '-DCONFIG_LINUX_SPI=1' ],
  },
  'mstarddc_spi' : {
    'systems' : [ 'linux' ],
    'deps'    : [ linux_headers ],
    'groups'  : [ group_i2c ],
    'srcs'    : files('mstarddc_spi.c'),
    'flags'   : [ '-DCONFIG_MSTARDDC_SPI=1' ],
    'default' : false
  },
  'nic3com' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_port_io ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('nic3com.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_NIC3COM=1' ],
  },
  'nicintel' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('nicintel.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_NICINTEL=1' ],
  },
  'nicintel_eeprom' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('nicintel_eeprom.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_NICINTEL_EEPROM=1' ],
  },
  'nicintel_spi' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('nicintel_spi.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_NICINTEL_SPI=1' ],
  },
  'nicnatsemi' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_port_io ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('nicnatsemi.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_NICNATSEMI=1' ],
    'default' : false, # not complete nor tested
  },
  'nicrealtek' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_port_io ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('nicrealtek.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_NICREALTEK=1' ],
  },
  'ogp_spi' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('ogp_spi.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_OGP_SPI=1' ],
  },
  'pickit2_spi' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_external ],
    'srcs'    : files('pickit2_spi.c'),
    'flags'   : [ '-DCONFIG_PICKIT2_SPI=1' ],
  },
  'pony_spi' : {
    'systems' : systems_serial,
    'groups'  : [ group_serial, group_external ],
    'srcs'    : files('pony_spi.c', 'serial.c', custom_baud_c),
    'flags'   : [ '-DCONFIG_PONY_SPI=1' ],
  },
  'rayer_spi' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_port_io ],
    'groups'  : [ group_internal ],
    'srcs'    : files('rayer_spi.c'),
    'flags'   : [ '-DCONFIG_RAYER_SPI=1' ],
  },
  'satamv' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_port_io, cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('satamv.c', 'pcidev.c'),
    'flags'   : ['-DCONFIG_SATAMV=1'],
  },
  'satasii' : {
    'systems' : systems_hwaccess,
    'cpu_families' : [ cpus_raw_mem ],
    'deps'    : [ libpci ],
    'groups'  : [ group_pci, group_internal ],
    'srcs'    : files('satasii.c', 'pcidev.c'),
    'flags'   : [ '-DCONFIG_SATASII=1' ],
  },
  'serprog' : {
    'systems' : systems_serial,
    'groups'  : [ group_serial, group_external ],
    'srcs'    : files('serprog.c', 'serial.c', custom_baud_c),
    'flags'   : [ '-DCONFIG_SERPROG=1' ],
  },
  'stlinkv3_spi' : {
    'deps'    : [ libusb1 ],
    'groups'  : [ group_usb, group_external ],
    'srcs'    : files('stlinkv3_spi.c', 'usbdev.c'),
    'flags'   : [ '-DCONFIG_STLINKV3_SPI=1' ],
  },
  'usbblaster_spi' : {
    'deps'    : [ libftdi1 ],
    'groups'  : [ group_ftdi, group_external ],
    'srcs'    : files('usbblaster_spi.c'),
    'flags'   : [ '-DCONFIG_USBBLASTER_SPI=1' ],
  },
}

active_programmer_count = 0
foreach p_name, p_data : programmer
  p_data += {
    'systems' : p_data.get('systems', ['all']),
    'cpu_families' : p_data.get('cpu_families', ['all']),
    'deps' : p_data.get('deps', []),
    'groups' : p_data.get('groups', []),
    'srcs' : p_data.get('srcs', []),
    'flags' : p_data.get('flags', []),
    'default' : p_data.get('default', true),
  }

  active        = false
  deps_found    = true
  not_found_dep = ''
  not_active_message = ''
  selected_hard = p_name in get_option('programmer')
  selected_soft = p_data.get('groups').contains(true) or \
                  'all' in get_option('programmer') or \
                  'auto' in get_option('programmer') and p_data.get('default')

  available = (p_data.get('systems') == ['all'] or p_data.get('systems').contains(host_machine.system()))
  if p_data.get('cpu_families') != ['all']
    foreach families_list : p_data.get('cpu_families')
      available = available and families_list.contains(host_machine.cpu_family())
    endforeach
  endif

  foreach dep : p_data.get('deps')
    if not dep.found()
      deps_found = false
      not_found_dep = dep.name()
      break
    endif
  endforeach

  if selected_hard
    if not available
      error(p_name + ' selected but not supported on this platform')
    elif not deps_found
      error(p_name + ' selected but dependency ' + not_found_dep +'not found')
    else
      active = true
    endif
  elif selected_soft
    if not available
      not_active_message = 'Not available on platform'
    elif not deps_found
      not_active_message = 'dependency ' + not_found_dep + ' not found'
    else
      active = true
    endif
  else
    not_active_message = 'not selected'
  endif

  p_data += {
    'active' : active,
    'summary' : not_active_message,
  }
  programmer += {p_name : p_data}
  if active
    active_programmer_count += 1
  endif
endforeach

if active_programmer_count == 0
  error('At least one programmer must be selected')
endif

# add srcs, cargs & deps from active programmer to global srcs, cargs & deps
foreach p_name, p_data : programmer
  if p_data.get('active')
    srcs += p_data.get('srcs')
    cargs += p_data.get('flags')
    deps += p_data.get('deps')
  endif
endforeach

if config_print_wiki.enabled()
  if get_option('classic_cli').disabled()
    error('`classic_cli_print_wiki` can not be enabled without `classic_cli`')
  else
    srcs += files('print_wiki.c')
    cargs += '-DCONFIG_PRINT_WIKI=1'
  endif
endif

if config_default_programmer_name != ''
  cargs += '-DCONFIG_DEFAULT_PROGRAMMER_NAME=&programmer_' + config_default_programmer_name
else
  cargs += '-DCONFIG_DEFAULT_PROGRAMMER_NAME=NULL'
endif

cargs += '-DCONFIG_DEFAULT_PROGRAMMER_ARGS="' + config_default_programmer_args + '"'

install_headers([
    'include/libflashprog.h',
  ],
)

include_dir = include_directories('include')

mapfile = 'libflashprog.map'
if host_machine.system() == 'darwin'
  vflag = ''
else
  vflag = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), mapfile)
endif
libflashprog = both_libraries(
  'flashprog',
  sources : [
    srcs,
  ],
  include_directories : include_dir,
  soversion : lt_current,
  version : lt_version,
  dependencies : [
    deps,
  ],
  c_args : [
    cargs,
  ],
  install : true,
  link_args : vflag,
  link_depends : mapfile,
)

version = meson.project_version()
#strip leading characters
if version.startswith('v')
  version = version.split('v')[1]
endif
if version.startswith('p')
  version = version.split('p')[1]
endif

pkgg = import('pkgconfig')
pkgg.generate(
  libraries : libflashprog,
  version : version,
  name : 'flashprog',
  filebase : 'flashprog',
  description : 'library to interact with flashprog',
)

config_manfile = configuration_data()
config_manfile.set('VERSION', version)
config_manfile.set('MAN_DATE', run_command('util/getversion.sh', '--man-date', check : true).stdout().strip())
configure_file(
  input : 'flashprog.8.tmpl',
  output : 'flashprog.8',
  configuration : config_manfile,
  install: true,
  install_dir: join_paths(get_option('mandir'), 'man8'),
)

if get_option('classic_cli').auto() or get_option('classic_cli').enabled()
  executable(
    'flashprog',
    files(
      'cli_classic.c',
      'cli_common.c',
      'cli_output.c',
    ),
    c_args : cargs,
    include_directories : include_dir,
    install : true,
    install_dir : get_option('sbindir'),
    link_with : libflashprog.get_static_lib(), # flashprog needs internal symbols of libflashprog
  )
endif

if get_option('ich_descriptors_tool').auto() or get_option('ich_descriptors_tool').enabled()
  subdir('util/ich_descriptors_tool')
endif

programmer_names_active     = []
programmer_names_not_active = []
foreach p_name, p_data : programmer
  if p_data.get('active')
    programmer_names_active += p_name
  else
    programmer_names_not_active += p_name + ' (' + p_data.get('summary', '') + ')'
  endif
endforeach

summary({
  'active' : [programmer_names_active],
  'non active' : [programmer_names_not_active],
}, section : 'Programmer')
