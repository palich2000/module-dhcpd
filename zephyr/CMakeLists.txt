find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

if(CONFIG_LIBDHCPD)
  zephyr_include_directories(include)
  add_subdirectory(.. build)
  set_property(GLOBAL APPEND PROPERTY ZEPHYR_INTERFACE_LIBS dhcpd)
  #zephyr_interface_library_named(dhcpd)
endif()