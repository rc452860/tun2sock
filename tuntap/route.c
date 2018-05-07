//
// Created by rc452 on 2018/5/4.
//

#include <winsock2.h>
#include "route.h"
#include "tapwin32-funcs.h"
#include "misc/socket_gc.h"

static bool add_route_ipapi(route_ipv4_t *r, DWORD index, DWORD metric);


bool add_route_ipapi(route_ipv4_t *r, DWORD index, DWORD metric) {
    struct gc_arena gc = gc_new();
    bool ret = false;
    DWORD status;

    if (index != TUN_ADAPTER_INDEX_INVALID) {
        MIB_IPFORWARDROW fr;
        CLEAR(fr);
        fr.dwForwardDest = htonl(r->network);
        fr.dwForwardMask = htonl(r->netmask);
        fr.dwForwardPolicy = 0;
        fr.dwForwardNextHop = htonl(r->gateway);
        fr.dwForwardIfIndex = index;
        fr.dwForwardType = 4; /* the next hop is not the final dest */
        fr.dwForwardProto = 3; /* PROTO_IP_NETMGMT */
        fr.dwForwardAge = 0;
        fr.dwForwardNextHopAS = 0;
        fr.dwForwardMetric1 = (r->flags & RT_METRIC_DEFINED) ? r->metric : 1;
        fr.dwForwardMetric2 = METRIC_NOT_USED;
        fr.dwForwardMetric3 = METRIC_NOT_USED;
        fr.dwForwardMetric4 = METRIC_NOT_USED;
        fr.dwForwardMetric5 = METRIC_NOT_USED;

        if ((r->network & r->netmask) != r->network) {
            printf("Warning: address %s is not a network address in relation to netmask %s",
                   print_in_addr_t(r->network, 0, &gc),
                   print_in_addr_t(r->netmask, 0, &gc));
        }

        status = CreateIpForwardEntry(&fr);

        if (status == NO_ERROR) {
            ret = true;
        } else {
            /* failed, try increasing the metric to work around Vista issue */
            const unsigned int forward_metric_limit = 2048; /* iteratively retry higher metrics up to this limit */

            for (; fr.dwForwardMetric1 <= forward_metric_limit; ++fr.dwForwardMetric1) {
                /* try a different forward type=3 ("the next hop is the final dest") in addition to 4.
                 * --redirect-gateway over RRAS seems to need this. */
                for (fr.dwForwardType = 4; fr.dwForwardType >= 3; --fr.dwForwardType) {
                    status = CreateIpForwardEntry(&fr);
                    if (status == NO_ERROR) {
                        printf(
                                "ROUTE: CreateIpForwardEntry succeeded with dwForwardMetric1=%u and dwForwardType=%u",
                                (unsigned int) fr.dwForwardMetric1,
                                (unsigned int) fr.dwForwardType);
                        ret = true;
                        goto doublebreak;
                    } else if (status != ERROR_BAD_ARGUMENTS) {
                        goto doublebreak;
                    }
                }
            }

            doublebreak:
            if (status != NO_ERROR) {
//                printf( "ROUTE: route addition failed using CreateIpForwardEntry: %s [status=%u if_index=%u]",
//                    strerror_win32(status, &gc),
//                    (unsigned int) status,
//                    (unsigned int) if_index);
            }
        }
    }

    gc_free(&gc);
    return ret;
}