//
// Created by rc452 on 2018/5/4.
//

#ifndef BADVPN_SOCKET_GC_H
#define BADVPN_SOCKET_GC_H

/*
 * Convert an in_addr_t in host byte order
 * to an ascii dotted quad.
 */
const char *
print_in_addr_t(in_addr_t addr, unsigned int flags, struct gc_arena *gc)
{
    struct in_addr ia;
    struct buffer out = alloc_buf_gc(64, gc);

    if (addr || !(flags & IA_EMPTY_IF_UNDEF))
    {
        CLEAR(ia);
        ia.s_addr = (flags & IA_NET_ORDER) ? addr : htonl(addr);

        buf_printf(&out, "%s", inet_ntoa(ia));
    }
    return BSTR(&out);
}

#endif //BADVPN_SOCKET_GC_H
