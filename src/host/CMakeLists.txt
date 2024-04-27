set (CMAKE_CXX_STANDARD 17)
add_definitions(-DHOST_MAC -DUSE_CONFIG_UV_THREADS -DSIZE_THREAD_POOL=128 -DHDC_HOST -DHOST_LINUX -DHARMONY_PROJECT -DTEST_HASH -DHDC_MSG_HASH="TEST")

AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_LIST_DIR} HOST_SRCS)
AUX_SOURCE_DIRECTORY(${CMAKE_CURRENT_LIST_DIR}/../common COMMON_SRCS)

get_filename_component(MY_RESULT_ABSOLUTE_PATH_VAR
                       "${CMAKE_CURRENT_LIST_DIR}/${MY_RELATIVE_PATH_VAR}"
                       ABSOLUTE)

# message(FATAL_ERROR "${}")

include_directories(/opt/homebrew/include/)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../common)
include_directories(/Users/wetest/workplace/openharmoney/third_party_bounds_checking_function/include)
include_directories(${ohos_top}/third_party/libusb/include)

FIND_LIBRARY(IOKit_LIBRARY IOKit)
FIND_LIBRARY(Foundation_LIBRARY Foundation)
FIND_LIBRARY(Security_LIBRARY Security)

link_libraries(uv crypto lz4
    /opt/homebrew/lib/libusb-1.0.a
    /opt/homebrew/lib/libuv.a
    /Users/wetest/workplace/openharmoney/third_party_bounds_checking_function/obj/libsecurec.a
    ${Foundation_LIBRARY} ${IOKit_LIBRARY} ${Security_LIBRARY}
    )

# link_libraries(uv crypto lz4
#     ${ohos_top}/out/sdk/clang_x64/obj/third_party/bounds_checking_function/libsec_static.a
#     ${ohos_top}/out/sdk/clang_x64/common/common/libusb_shared.so)

add_executable(hdc ${COMMON_SRCS} ${HOST_SRCS})
