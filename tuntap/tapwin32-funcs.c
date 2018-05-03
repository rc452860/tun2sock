/**
 * @file tapwin32-funcs.c
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <misc/debug.h>
#include <misc/ipaddr.h>
#include <misc/maxalign.h>
#include <misc/strdup.h>

#include "wintap-common.h"

#include <tuntap/tapwin32-funcs.h>
#include <structure/LinkedList1.h>
#include <misc/offset.h>
#include <Iphlpapi.h>
#include <errno.h>
#include <winioctl.h>
#include "tap-windows.h"
#include <unistd.h>
#include <winsock2.h>
#include <Shellapi.h>

#define _UNICODE

// 适配器列表
LinkedList1 adapter_info_list;

int adapter_index_init();

int config_adapter(AdapterInfo_t *adapterInfo);

int exec_as_admin(const char* app,const char* param);

static int split_spec(char *name, char *sep, char **out_fields[], int num_fields) {
    ASSERT(num_fields > 0)
    ASSERT(strlen(sep) > 0)

    size_t seplen = strlen(sep);

    int i = 0;
    while (i < num_fields - 1) {
        char *s = strstr(name, sep);
        if (!s) {
            DEBUG("missing separator number %d", (i + 1));
            goto fail;
        }

        if (!(*out_fields[i] = b_strdup_bin(name, s - name))) {
            DEBUG("b_strdup_bin failed");
            goto fail;
        }

        name = s + seplen;
        i++;
    }

    if (!(*out_fields[i] = b_strdup(name))) {
        DEBUG("b_strdup_bin failed");
        goto fail;
    }

    return 1;

    fail:
    while (i-- > 0) {
        free(*out_fields[i]);
    }
    return 0;
}

int tapwin32_parse_tap_spec(char *name, char **out_component_id, char **out_human_name) {
    char **out_fields[2];
    out_fields[0] = out_component_id;
    out_fields[1] = out_human_name;

    return split_spec(name, ":", out_fields, 2);
}

int tapwin32_parse_tun_spec(char *name, char **out_component_id, char **out_human_name, uint32_t out_addrs[3]) {
    char *addr_strs[3];

    char **out_fields[5];
    out_fields[0] = out_component_id;
    out_fields[1] = out_human_name;
    out_fields[2] = &addr_strs[0];
    out_fields[3] = &addr_strs[1];
    out_fields[4] = &addr_strs[2];

    if (!split_spec(name, ":", out_fields, 5)) {
        goto fail0;
    }

    for (int i = 0; i < 3; i++) {
        if (!ipaddr_parse_ipv4_addr(MemRef_MakeCstr(addr_strs[i]), &out_addrs[i])) {
            goto fail1;
        }
    }

    free(addr_strs[0]);
    free(addr_strs[1]);
    free(addr_strs[2]);

    return 1;

    fail1:
    free(*out_component_id);
    free(*out_human_name);
    free(addr_strs[0]);
    free(addr_strs[1]);
    free(addr_strs[2]);
    fail0:
    return 0;
}

int tapwin32_find_device(char *device_component_id, char *device_name, char (*device_path)[TAPWIN32_MAX_REG_SIZE]) {
    // open adapter key
    // used to find all devices with the given ComponentId
    HKEY adapter_key;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapter_key) != ERROR_SUCCESS) {
        DEBUG("Error opening adapter key");
        return 0;
    }
    char net_cfg_instance_id[TAPWIN32_MAX_REG_SIZE];
    int found = 0;
    int pres;

    DWORD i;
    for (i = 0;; i++) {
        DWORD len;
        DWORD type;

        char key_name[TAPWIN32_MAX_REG_SIZE];
        len = sizeof(key_name);
        if (RegEnumKeyEx(adapter_key, i, key_name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }

        char unit_string[TAPWIN32_MAX_REG_SIZE];
        pres = _snprintf(unit_string, sizeof(unit_string), "%s\\%s", ADAPTER_KEY, key_name);
        if (pres < 0 || pres == sizeof(unit_string)) {
            continue;
        }
        HKEY unit_key;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, unit_string, 0, KEY_READ, &unit_key) != ERROR_SUCCESS) {
            continue;
        }

        char component_id[TAPWIN32_MAX_REG_SIZE];
        len = sizeof(component_id);
        if (RegQueryValueEx(unit_key, "ComponentId", NULL, &type, (LPBYTE) component_id, &len) != ERROR_SUCCESS ||
            type != REG_SZ) {
            ASSERT_FORCE(RegCloseKey(unit_key) == ERROR_SUCCESS)
            continue;
        }

        len = sizeof(net_cfg_instance_id);
        if (RegQueryValueEx(unit_key, "NetCfgInstanceId", NULL, &type, (LPBYTE) net_cfg_instance_id, &len) !=
            ERROR_SUCCESS || type != REG_SZ) {
            ASSERT_FORCE(RegCloseKey(unit_key) == ERROR_SUCCESS)
            continue;
        }

        RegCloseKey(unit_key);

        // check if ComponentId matches
        if (!strcmp(component_id, device_component_id)) {
            // if no name was given, use the first device with the given ComponentId
            if (!device_name) {
                found = 1;
                break;
            }

            // open connection key
            char conn_string[TAPWIN32_MAX_REG_SIZE];
            pres = _snprintf(conn_string, sizeof(conn_string), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY,
                             net_cfg_instance_id);
            if (pres < 0 || pres == sizeof(conn_string)) {
                continue;
            }
            HKEY conn_key;
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, conn_string, 0, KEY_READ, &conn_key) != ERROR_SUCCESS) {
                continue;
            }

            // read name
            char name[TAPWIN32_MAX_REG_SIZE];
            len = sizeof(name);
            if (RegQueryValueEx(conn_key, "Name", NULL, &type, (LPBYTE) name, &len) != ERROR_SUCCESS ||
                type != REG_SZ) {
                ASSERT_FORCE(RegCloseKey(conn_key) == ERROR_SUCCESS)
                continue;
            }

            ASSERT_FORCE(RegCloseKey(conn_key) == ERROR_SUCCESS)

            // check name
            if (!strcmp(name, device_name)) {
                found = 1;
                break;
            }
        }
    }

    ASSERT_FORCE(RegCloseKey(adapter_key) == ERROR_SUCCESS)

    if (!found) {
        return 0;
    }

    pres = _snprintf(*device_path, sizeof(*device_path), "\\\\.\\Global\\%s.tap", net_cfg_instance_id);
    if (pres < 0 || pres == sizeof(*device_path)) {
        return 0;
    }

    return 1;
}

int adapter_info_list_init() {

    LinkedList1_Init(&adapter_info_list);
    char *device_component_id = "tap0901";
    HKEY adapter_key;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapter_key) != ERROR_SUCCESS) {
        DEBUG("Error opening adapter key");
        return 0;
    }
    int pres;

    DWORD i, cSubKeys = 0;               // number of subkeys
    TCHAR achValue[TAPWIN32_MAX_REG_SIZE];
    DWORD cchValue = TAPWIN32_MAX_REG_SIZE;

    // Get the class name and the value count.
    DWORD retcode;
    if ((retcode = RegQueryInfoKey(adapter_key, NULL, NULL, NULL, &cSubKeys, NULL, NULL, NULL, NULL, NULL, NULL,
                                   NULL)) != ERROR_SUCCESS) {
        return retcode;
    }
    char net_cfg_instance_id[TAPWIN32_MAX_REG_SIZE];
    /* interface human name array */
    int devices_len = 0;
    // 遍历所有适配器信息，寻找我们需要的tap0901
    for (i = 0; i < cSubKeys; i++) {
        DWORD len;
        DWORD type;
        char key_name[TAPWIN32_MAX_REG_SIZE];
        len = sizeof(key_name);
        if (RegEnumKeyEx(adapter_key, i, key_name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break;
        }
        char unit_string[TAPWIN32_MAX_REG_SIZE];
        pres = _snprintf(unit_string, sizeof(unit_string), "%s\\%s", ADAPTER_KEY, key_name);
        if (pres < 0 || pres == sizeof(unit_string)) {
            continue;
        }
        HKEY unit_key;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, unit_string, 0, KEY_READ, &unit_key) != ERROR_SUCCESS) {
            continue;
        }

        char component_id[TAPWIN32_MAX_REG_SIZE];
        len = sizeof(component_id);
        if (RegQueryValueEx(unit_key, "ComponentId", NULL, &type, (LPBYTE) component_id, &len) != ERROR_SUCCESS ||
            type != REG_SZ) {
            ASSERT_FORCE(RegCloseKey(unit_key) == ERROR_SUCCESS)
            continue;
        }

        len = sizeof(net_cfg_instance_id);
        if (RegQueryValueEx(unit_key, "NetCfgInstanceId", NULL, &type, (LPBYTE) net_cfg_instance_id, &len) !=
            ERROR_SUCCESS || type != REG_SZ) {
            ASSERT_FORCE(RegCloseKey(unit_key) == ERROR_SUCCESS)
            continue;
        }
        char mtu[TAPWIN32_MAX_REG_SIZE];
        len = sizeof(mtu);
        if (RegQueryValueEx(unit_key, "MTU", NULL, &type, (LPBYTE) mtu, &len) != ERROR_SUCCESS || type != REG_SZ) {
            ASSERT_FORCE(RegCloseKey(unit_key) == ERROR_SUCCESS)
            continue;
        }
        RegCloseKey(unit_key);

        // check if ComponentId matches
        if (!strcmp(component_id, device_component_id)) {


            char conn_string[TAPWIN32_MAX_REG_SIZE];
            pres = _snprintf(conn_string, sizeof(conn_string), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY,
                             net_cfg_instance_id);
            if (pres < 0 || pres == sizeof(conn_string)) {
                continue;
            }
            HKEY conn_key;
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, conn_string, 0, KEY_READ, &conn_key) != ERROR_SUCCESS) {
                continue;
            }

            // read name
            char name[TAPWIN32_MAX_REG_SIZE];
            len = sizeof(name);
            if (RegQueryValueEx(conn_key, "Name", NULL, &type, (LPBYTE) name, &len) != ERROR_SUCCESS ||
                type != REG_SZ) {
                ASSERT_FORCE(RegCloseKey(conn_key) == ERROR_SUCCESS)
                continue;
            }

            ASSERT_FORCE(RegCloseKey(conn_key) == ERROR_SUCCESS)
            devices_len++;
            // 初始化adapterInfo来存储适配器信息
            AdapterInfo_t *adapterInfo = (AdapterInfo_t *) malloc(sizeof(AdapterInfo_t));
            memcpy(adapterInfo->net_cfg_instance_id, net_cfg_instance_id, TAPWIN32_MAX_REG_SIZE);
            // 设置MTU
            sscanf(mtu, "%d", &adapterInfo->mtu);
            memcpy(adapterInfo->name, name, TAPWIN32_MAX_REG_SIZE);
            // 添加到适配器列表中
            LinkedList1_Append(&adapter_info_list, &adapterInfo->list_node);
        }

    }
    adapter_index_init();
}

int adapter_index_init() {
    printf("index start\n");
    // 查找适配器的index
    if (!LinkedList1_IsEmpty(&adapter_info_list)) {
        for (LinkedList1Node *node = LinkedList1_GetFirst(&adapter_info_list); node; node = LinkedList1Node_Next(
                node)) {
            AdapterInfo_t *adapterInfo = UPPER_OBJECT(node, AdapterInfo_t, list_node);
            int len = MultiByteToWideChar(CP_ACP, 0, adapterInfo->net_cfg_instance_id, -1, NULL, 0);
            wchar_t interface_name[256];
            snwprintf(interface_name, sizeof(interface_name), L"\\DEVICE\\TCPIP_%S", adapterInfo->net_cfg_instance_id);

            MIB_IFTABLE *pIfTable = malloc(sizeof(MIB_IFTABLE));
            if (pIfTable == NULL) {
                printf("Error allocating memory needed to call GetIfTable\n");
                return 1;
            }
            DWORD dwSize = sizeof(MIB_IFTABLE);

            DWORD dwRetVal;
            if (GetIfTable(pIfTable, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                free(pIfTable);
                pIfTable = (MIB_IFTABLE *) malloc(dwSize);
                if (pIfTable == NULL) {
                    printf("Error allocating memory needed to call GetIfTable\n");
                    return 1;
                }
            }
            if ((dwRetVal = GetIfTable(pIfTable, &dwSize, FALSE)) == NO_ERROR) {
                for (int i = 0; i < pIfTable->dwNumEntries; i++) {
                    MIB_IFROW *mib_ifrow = &pIfTable->table[i];
                    switch (mib_ifrow->dwOperStatus) {
                        case IF_OPER_STATUS_NON_OPERATIONAL:
                            printf("Non Operational\n");
                            break;
                        case IF_OPER_STATUS_UNREACHABLE:
                            printf("Unreachable\n");
                            break;
                        case IF_OPER_STATUS_DISCONNECTED:
                            printf("Disconnected\n");
                            break;
                        case IF_OPER_STATUS_CONNECTING:
                            printf("Connecting\n");
                            break;
                        case IF_OPER_STATUS_CONNECTED:
                            printf("Connected\n");
                            break;
                        case IF_OPER_STATUS_OPERATIONAL:
                            printf("Operational\n");
                            break;
                        default:
                            printf("Unknown status %ld\n", mib_ifrow->dwAdminStatus);
                            break;
                    }

                    if (wcscmp(mib_ifrow->wszName, interface_name) == 0) {
                        adapterInfo->index = mib_ifrow->dwIndex;
                    }
                }
            } else {
                printf("GetIfTable failed with error: %d\n", dwRetVal);
            }
        }
    }
    printf("index end\n");
}

//  netsh interface ip set address my-tap static 10.3.0.1 255.255.255.0
int config_adapter(AdapterInfo_t *adapterInfo) {
// 方案一
//    char cmd[256];
//    snprintf(cmd, sizeof(cmd),
//             "netsh interface ip set address \"%s\" static %s %",
//             adapterInfo->name,
//             DEFAULT_IPV4_ADDRESS,
//             DEFAULT_IPV4_NETMASK
//    );
//    printf(cmd);
//    return system(cmd);

// 方案二
//    printf("adapter name : %s\n", adapterInfo->name);
//    IPAddr ipAddr = inet_addr(DEFAULT_IPV4_ADDRESS);
//    IPMask ipMask = inet_addr(DEFAULT_IPV4_NETMASK);
//
//    printf("%u %u\n", ipAddr, ipMask);
//    ULONG NTEContext = 0;
//    ULONG NTEInstance = 0;
//    DWORD result =  AddIPAddress(
//            ipAddr,
//            ipMask,
//            (DWORD)adapterInfo->index,
//            &NTEContext,
//            &NTEInstance
//    );
//    return (int)result;

//方案三
    char param[256];
    snprintf(param,sizeof(param),
    "interface ip set address \"%s\" static %s %s",
             adapterInfo->name,
             DEFAULT_IPV4_ADDRESS,
             DEFAULT_IPV4_NETMASK
    );
    return exec_as_admin("netsh", param);

}

int open_tun() {
    adapter_info_list_init();
    HANDLE handle;
    AdapterInfo_t *adapterInfoUsed = NULL;
    for (LinkedList1Node *node = LinkedList1_GetFirst(&adapter_info_list); node; node = LinkedList1Node_Next(node)) {
        AdapterInfo_t *adapterInfo = UPPER_OBJECT(node, AdapterInfo_t, list_node);
        // 打开设备
        char device_path[TAPWIN32_MAX_REG_SIZE];
        _snprintf(device_path, sizeof(device_path), "\\\\.\\Global\\%s.tap", adapterInfo->net_cfg_instance_id);
        printf("current device path: %s\n", device_path);
        handle = CreateFile(device_path,
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            0,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                            0);
        if (handle == INVALID_HANDLE_VALUE) {
            printf("CreateFile failed on TAP device: %s", device_path);
        } else {
            adapterInfoUsed = adapterInfo;
            break;
        }
    }

    if (adapterInfoUsed == NULL) {
        printf("not available adaptr\n");
        return -1;
    }

    // 获得MTU
    {
        int len;
        u_long mtu;
        if (DeviceIoControl(handle, TAP_IOCTL_GET_MTU, &mtu, sizeof(mtu), &mtu, sizeof(mtu), &len, NULL)) {
            adapterInfoUsed->mtu = (int) mtu;
            printf("adaptr %s mtu:%d\n", adapterInfoUsed->name, adapterInfoUsed->mtu);
        } else {

        }
    }

    // 获得驱动版本
    {
        int len;
        u_long info[3] = {};
        if (DeviceIoControl(handle, TAP_WIN_IOCTL_GET_VERSION,
                            &info, sizeof(info),
                            &info, sizeof(info), &len, NULL)) {
            printf("TAP-Windows Driver Version %d.%d %s\n",
                   (int) info[0],
                   (int) info[1],
                   (info[2] ? "(DEBUG)" : ""));

        }
    }

    // 初始化网卡
    {
        /*
         * 1. ipaddress
         * 2. gateway
         * 3. netmask
         *
         * note: 2 = 1 & 3
         */
        uint32_t tun_addrs[3] = {0};
        ipv4_string_to_int(DEFAULT_IPV4_ADDRESS, &tun_addrs[0]);
        ipv4_string_to_int(DEFAULT_IPV4_NETMASK, &tun_addrs[2]);
        tun_addrs[1] = tun_addrs[0] & tun_addrs[2];

        int len;
        if (DeviceIoControl(handle, TAP_IOCTL_CONFIG_TUN, tun_addrs, sizeof(tun_addrs), tun_addrs, sizeof(tun_addrs),
                            &len, NULL)) {
            char ipv4_address[32] = {0};
            char ipv4_gateway[32] = {0};
            char ipv4_netmask[32] = {0};
            ipaddr_print_addr(tun_addrs[0], ipv4_address);
            ipaddr_print_addr(tun_addrs[1], ipv4_gateway);
            ipaddr_print_addr(tun_addrs[2], ipv4_netmask);

            printf("tun subnet config success with network/local/netmask: = %s %s %s\n",
                   ipv4_address,
                   ipv4_gateway,
                   ipv4_netmask
            );
        } else {
            printf("tun subnet config error\n");
            return -1;
        }
    }
    // 设置ip地址
    {
        int status = config_adapter(adapterInfoUsed);
        printf("%d\n", status);
    }

    {
        ULONG upstatus = TRUE;
        int len;
        if (!DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS, &upstatus, sizeof(upstatus), &upstatus, sizeof(upstatus), &len, NULL)) {
            printf("connection faild");
        }
    }
    for (int i = 0; i < 15; ++i) {
        sleep(1);
    }

}

int exec_as_admin(const char* app,const char* param){
    SHELLEXECUTEINFO shellexecuteinfo;
    memset(&shellexecuteinfo, 0, sizeof(shellexecuteinfo));
    shellexecuteinfo.cbSize = sizeof(shellexecuteinfo);
    shellexecuteinfo.hwnd = NULL;
    shellexecuteinfo.lpVerb = TEXT("runas");
    shellexecuteinfo.lpFile = TEXT(app);
    shellexecuteinfo.lpParameters = TEXT(param);

    shellexecuteinfo.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteEx(&shellexecuteinfo)){
        DWORD dwStatus = GetLastError();
        if (dwStatus == ERROR_CANCELLED){
            printf("user cancelled");
            return ERROR_CANCELLED;
        }else if(dwStatus == ERROR_FILE_NOT_FOUND){
            printf("error file not found");
            return ERROR_FILE_NOT_FOUND;
        }else{
            return dwStatus;
        }
    }
    return 0;
}