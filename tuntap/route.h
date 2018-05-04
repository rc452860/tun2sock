//
// Created by rc452 on 2018/5/4.
//

#ifndef BADVPN_ROUTE_H
#define BADVPN_ROUTE_H

#include "misc/basic.h"
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#endif

#define METRIC_NOT_USED ((DWORD)-1)

#define in_addr_t uint32_t


struct route_ipv4 {
#define RT_DEFINED        (1<<0)
#define RT_ADDED          (1<<1)
#define RT_METRIC_DEFINED (1<<2)
    struct route_ipv4 *next;
    unsigned int flags;
    const struct route_option *option;
    in_addr_t network;
    in_addr_t netmask;
    in_addr_t gateway;
    int metric;
};
typedef struct route_ipv4 route_ipv4_t;

/**
 * 添加路由
 * @param r
 * @param index
 * @param metric
 * @return
 */
bool add_route_ipapi(route_ipv4_t *r,DWORD index,DWORD metric);
#endif //BADVPN_ROUTE_H
