/**
 * @file tapwin32-funcs.h
 * @author Ambroz Bizjak <ambrop7@gmail.com>
 * 
 * @section LICENSE
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef BADVPN_TUNTAP_TAPWIN32_FUNCS_H
#define BADVPN_TUNTAP_TAPWIN32_FUNCS_H

#include <stdint.h>
#include <windows.h>
#include <structure/LinkedList1.h>
#include <iptypes.h>
#include <iphlpapi.h>

#define TAPWIN32_MAX_REG_SIZE 256
#define TUN_ADAPTER_INDEX_INVALID -1
/*
 * example:  netsh interface ip set address my-tap static 10.3.0.1 255.255.255.0
 * blow Is ipv4 address and netmask
 * */
#define DEFAULT_IPV4_ADDRESS "10.3.0.1"
#define DEFAULT_IPV4_NETMASK "255.255.255.0"

struct AdapterInfo{
    char name[TAPWIN32_MAX_REG_SIZE];                       // 适配器名称
    int mtu;                                                // 适配器MTU
    char net_cfg_instance_id[TAPWIN32_MAX_REG_SIZE];        // 适配器地址
    int index;                                              // 适配器索引
    LinkedList1Node list_node;                              // 链表NODE
} ;
typedef struct AdapterInfo AdapterInfo_t;
/*
 * 可用网络适配器列表
 */
extern LinkedList1 adapter_info_list;



int tapwin32_parse_tap_spec (char *name, char **out_component_id, char **out_human_name);
int tapwin32_parse_tun_spec (char *name, char **out_component_id, char **out_human_name, uint32_t out_addrs[3]);
int tapwin32_find_device (char *device_component_id, char *device_name, char (*device_path)[TAPWIN32_MAX_REG_SIZE]);
int tapwin32_config(char* new_device_name,char **devices);
int adapter_info_list_init();

IP_ADAPTER_INFO *get_adapter_info_list(struct gc_arena *gc)
{
    ULONG size = 0;
    IP_ADAPTER_INFO *pi = NULL;
    DWORD status;

    if ((status = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    {
        msg(M_INFO, "GetAdaptersInfo #1 failed (status=%u) : %s",
            (unsigned int)status,
            strerror_win32(status, gc));
    }
    else
    {
        pi = (PIP_ADAPTER_INFO) gc_malloc(size, false, gc);
        if ((status = GetAdaptersInfo(pi, &size)) != NO_ERROR)
        {
            msg(M_INFO, "GetAdaptersInfo #2 failed (status=%u) : %s",
                (unsigned int)status,
                strerror_win32(status, gc));
            pi = NULL;
        }
    }
    return pi;
}
int open_tun();
#endif
