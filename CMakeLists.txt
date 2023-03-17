project(dhcpd)
cmake_minimum_required(VERSION 3.20)
if(CONFIG_DHCPD)

  zephyr_include_directories(${ZEPHYR_BASE}/inlude)

  target_include_directories(dhcpd INTERFACE include)

  zephyr_library()

  file(GLOB_RECURSE SOURCES /src/*.c)
  zephyr_library_sources(${SOURCES})

endif(CONFIG_DHCPD)