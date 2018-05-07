set(TUNTAP_ADDITIONAL_SOURCES)
if (WIN32)
    list(APPEND TUNTAP_ADDITIONAL_SOURCES tapwin32-funcs.c route.c)
endif ()

set(TUNTAP_SOURCES
    BTap.c
    ${TUNTAP_ADDITIONAL_SOURCES}
)
badvpn_add_library(tuntap "system;flow;Iphlpapi" "" "${TUNTAP_SOURCES}")
