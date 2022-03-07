cmake_minimum_required (VERSION 3.10)
project(FUSE-NFS)


add_executable(fusenfs src/fusenfs.c)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE REQUIRED fuse3)
target_include_directories(fusenfs PRIVATE ${FUSE_INCLUDE_DIR})
target_link_libraries(fusenfs ${FUSE_LIBRARIES})

pkg_check_modules(LIBSSH2 REQUIRED libssh2)
target_include_directories(fusenfs PRIVATE ${LIBSSH2_INCLUDE_DIR})
target_link_libraries(fusenfs ${LIBSSH2_LIBRARIES})

# Tests
add_executable(rw_test src/test.c)
add_executable(nfs_better src/nfs_win.c)
add_executable(fusenfs_better src/fusenfs_win.c)