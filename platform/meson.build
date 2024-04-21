fs = import('fs')

srcs += files(
  ('endian_' + host_machine.endian() + '.c'),
  'memaccess.c',
)

if host_machine.endian() == 'little'
  add_project_arguments('-D__FLASHPROG_LITTLE_ENDIAN__=1', language : 'c')
endif
if host_machine.endian() == 'big'
  add_project_arguments('-D__FLASHPROG_BIG_ENDIAN__=1', language : 'c')
endif

# OpenBSD requires libi386 or libamd64 for I/O port handling
if host_machine.system() == 'openbsd'
  if host_machine.cpu_family() == 'x86'
    libi386 = cc.find_library('i386')
    deps += libi386
  elif host_machine.cpu_family() == 'x86_64'
    libamd64 = cc.find_library('amd64')
    deps += libamd64
  endif
endif

if host_machine.system() == 'netbsd'
  # NetBSD requires libi386 or libx86_64 for I/O port handling
  if host_machine.cpu_family() == 'x86'
    libi386 = cc.find_library('i386')
    deps += libi386
  elif host_machine.cpu_family() == 'x86_64'
    libx86_64 = cc.find_library('x86_64')
    deps += libx86_64
  endif
  # and special handling for `pci.h` not being inside `pci/`
  if fs.exists('/usr/pkg/include/pciutils/pci.h')
    add_project_arguments('-DPCIUTILS_PCI_H', language : 'c')
  endif
endif


# SunOS requires external libraries for network sockets
# they are used to support serial devices via network
if host_machine.system() == 'sunos'
  libsocket = cc.find_library('socket')
  libnsl = cc.find_library('nsl')
  deps += [ libsocket, libnsl]
endif
