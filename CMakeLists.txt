//project(dhcpd)
cmake_minimum_required(VERSION 3.20)

  zephyr_include_directories(${ZEPHYR_BASE}/inlude)

  target_include_directories(dhcpd INTERFACE include)

  zephyr_library()

 zephyr_library_sources(
  src/args.c
  src/bindings.c
  src/dhcpmem.c
  src/dhcpserver.c
  src/options.c
  )

