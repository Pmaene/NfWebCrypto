get_filename_component(TOOLCHAIN_DIR ${CMAKE_CURRENT_LIST_FILE} PATH)
include("${TOOLCHAIN_DIR}/common.cmake")

# NOTE: SECRET_SYSTEM_KEY should be changed for actual deployments.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSECRET_SYSTEM_KEY=iIniW9SVpZKlXGmbrgrJG9uxy7HtCNJsDM5IXS24eCI=")

# Toolchain paths - for OS X we just use the system tools
set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")
