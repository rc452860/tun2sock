//
// Created by rc452 on 2018/4/25.
//

#ifndef BADVPN_FILTER_H
#define BADVPN_FILTER_H

#include <structure/LinkedList1.h>
#include <misc/offset.h>

typedef void (*filter_operation_handler)(char* data,size_t len);

typedef struct {
    filter_operation_handler filter_operation;    //filter sender data
    LinkedList1Node list_node;  //list_node
} Filter;
LinkedList1 *filter_global = NULL;

void filter_init(){
    filter_global = (LinkedList1 *)malloc(sizeof(*filter_global));
    LinkedList1_Init(filter_global);
}
void filter_add(filter_operation_handler handler){
    Filter *filter = (Filter *) malloc(sizeof(Filter));
    filter->filter_operation = handler;
    LinkedList1_Append(filter_global,&filter->list_node);
}

void filter_destory(){
    LinkedList1Node *node;
    while (node = LinkedList1_GetFirst(filter_global)) {
        LinkedList1_Remove(filter_global, node);
        Filter *filter = UPPER_OBJECT(node, Filter, list_node);
        free(filter);
    }
    printf("%s\n", filter_global);
    free(filter_global);
    printf("%s\n", filter_global);
}

void handler_1(char *data,size_t len){
    printf("Nothing to do");
}
void test(){
    filter_init();
    for (int i = 0; i < 3; ++i) {
        filter_add(handler_1);
    }
    filter_destory();
}
#endif //BADVPN_FILTER_H
