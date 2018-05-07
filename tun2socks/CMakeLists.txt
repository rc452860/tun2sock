if(MINGW)
        set(CMAKE_RC_COMPILER_INIT windres)
        ENABLE_LANGUAGE(RC)
        SET(CMAKE_RC_COMPILE_OBJECT
                "<CMAKE_RC_COMPILER> -O coff <DEFINES> -i <SOURCE> -o <OBJECT>")
endif(MINGW)

add_executable(badvpn-tun2socks
    tun2socks.c
    SocksUdpGwClient.c
        test.c tun2socks.rc)
target_link_libraries(badvpn-tun2socks system flow tuntap lwip socksclient udpgw_client)

install(
    TARGETS badvpn-tun2socks
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(
    FILES badvpn-tun2socks.8
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
)
