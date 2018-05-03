set(SOURCE
        BSocksClient.c
        Filter.h)
badvpn_add_library(socksclient "system;flow;flowextra" "" ${SOURCE})
