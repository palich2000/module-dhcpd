project(dhcpd)
cmake_minimum_required(VERSION 3.20)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
add_library(dhcpd)
zephyr_include_directories(include)

target_compile_options(dhcpd PRIVATE -Wall -Wextra)
set_target_properties(dhcpd PROPERTIES C_STANDARD 11)

target_include_directories(dhcpd PUBLIC include)

zephyr_include_directories(.)
zephyr_library()
zephyr_library_sources(
args.c
bindings.c
dhcpmem.c
dhcpserver.c
options.c
)

file(CONFIGURE OUTPUT .gitignore
  NEWLINE_STYLE UNIX
  CONTENT "*")