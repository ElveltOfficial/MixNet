cmake_minimum_required(VERSION 3.8)

project(MXNClient C)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
    "$<IF:$<C_COMPILER_ID:MSVC>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

# libsodiumのインクルード・ライブラリパス（適宜修正）
set(LIBSODIUM_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(LIBSODIUM_LIB_DIR "${CMAKE_SOURCE_DIR}/lib")

include_directories(${LIBSODIUM_INCLUDE_DIR})
link_directories(${LIBSODIUM_LIB_DIR})

set(SOURCES
    MXNClient.c
    Crypto.c
    Packet.c
    Peer.c
    Route.c
    Network.c
    Tracker.c
)

add_executable(MXNClient ${SOURCES})

add_definitions(-DSODIUM_STATIC)

target_link_libraries(MXNClient libsodium)

set_property(TARGET MXNClient PROPERTY C_STANDARD 11)

# Windowsの場合はws2_32.libをリンク
if(WIN32)
    target_link_libraries(MXNClient ws2_32)
endif()
