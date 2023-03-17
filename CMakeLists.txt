
if(CONFIG_DHCPD)
zephyr_interface_library_named(dhcpd)

zephyr_include_directories(
  dhcpd INTERFACE
  ${ZEPHYR_BASE}/include
  include/
)

zephyr_library()

zephyr_library_sources(
  src/args.c
  src/bindings.c
  src/dhcpmem.c
  src/dhcpserver.c
  src/options.c
)

zephyr_library_link_libraries(dhcpd)

target_link_libraries(dhcpd INTERFACE zephyr_interface)
endif()
