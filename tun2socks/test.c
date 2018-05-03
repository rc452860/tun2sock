//
// Created by rc452 on 2018/4/28.
//
#include <tuntap/tapwin32-funcs.h>
#include <misc/offset.h>

int main(int argc,char **argv){
//    adapter_info_list_init();
//    for (LinkedList1Node *node = LinkedList1_GetFirst(&adapter_info_list); node; node = LinkedList1Node_Next(node)) {
//        AdapterInfo_t *adapterInfo = UPPER_OBJECT(node, AdapterInfo_t, list_node);
//        printf("%s - %d\n", adapterInfo->name,adapterInfo->index);
//    }
    open_tun();
}