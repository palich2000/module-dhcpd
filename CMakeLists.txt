project(dhcpd)
cmake_minimum_required(VERSION 3.20)

add_library(dhcpd)
zephyr_include_directories(include)

target_compile_options(dhcpd PRIVATE -Wall -Wextra)
set_target_properties(dhcpd PROPERTIES C_STANDARD 11)

target_include_directories(dhcpd PUBLIC include)
add_subdirectory(src)

file(CONFIGURE OUTPUT .gitignore
  NEWLINE_STYLE UNIX
  CONTENT "*")