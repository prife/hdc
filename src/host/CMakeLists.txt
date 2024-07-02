set (CMAKE_CXX_STANDARD 17)
# add_definitions(-DHOST_MAC -DUSE_CONFIG_UV_THREADS -DSIZE_THREAD_POOL=128 -DHDC_HOST -DHOST_LINUX -DHARMONY_PROJECT -DTEST_HASH -DHDC_MSG_HASH="TEST")

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_LIST_DIR} HOST_SRCS)
AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_LIST_DIR}/../common COMMON_SRCS)

get_filename_component(MY_RESULT_ABSOLUTE_PATH_VAR
                       "${CMAKE_CURRENT_LIST_DIR}/${MY_RELATIVE_PATH_VAR}"
                       ABSOLUTE)

# message(FATAL_ERROR "${}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-g)

# 确保 third_party_bounds_checking_function 与该git仓库同级别路径
set(third_party_srcpath ${CMAKE_CURRENT_LIST_DIR}/../../../)
AUX_SOURCE_DIRECTORY(${third_party_srcpath}/third_party_bounds_checking_function/src bounds_checking_srcs)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../common)
include_directories(${third_party_srcpath}/third_party_bounds_checking_function/include)

if(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
add_definitions(-DHOST_MAC -DUSE_CONFIG_UV_THREADS -DSIZE_THREAD_POOL=128 -DHDC_HOST -DHOST_LINUX -DHARMONY_PROJECT -DTEST_HASH -DHDC_MSG_HASH="TEST")
include_directories(/opt/homebrew/include/)
FIND_LIBRARY(IOKit_LIBRARY IOKit)
FIND_LIBRARY(Foundation_LIBRARY Foundation)
FIND_LIBRARY(Security_LIBRARY Security)

link_directories(/opt/homebrew/lib)
link_libraries(
    /opt/homebrew/lib/libusb-1.0.a
    /opt/homebrew/lib/libuv.a
    /opt/homebrew/lib/liblz4.a
    /opt/homebrew/lib/libcrypto.a
    ${Foundation_LIBRARY} ${IOKit_LIBRARY} ${Security_LIBRARY}
    )

elseif(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
add_definitions(-DUSE_CONFIG_UV_THREADS -DSIZE_THREAD_POOL=128 -DHDC_HOST -DHOST_LINUX -DHARMONY_PROJECT -DTEST_HASH -DHDC_MSG_HASH="TEST")
include_directories(/usr/include/libusb-1.0/
)
link_libraries(
    /usr/lib/aarch64-linux-gnu/libusb-1.0.a
    /usr/lib/aarch64-linux-gnu/libuv.a
    /lib/aarch64-linux-gnu/liblz4.a
    /lib/aarch64-linux-gnu/libcrypto.a
    crypto lz4 pthread udev dl
    )
endif()

add_executable(hdc ${COMMON_SRCS} ${HOST_SRCS} ${bounds_checking_srcs})

if(CMAKE_HOST_SYSTEM_NAME MATCHES "Linux")
# target_link_libraries(hdc dl)
target_link_options(hdc PRIVATE -static-libgcc -static-libstdc++)
endif()