/**
 * @file dhcpmem.h
 * @author Tsaplay Yuriy (y.tsaplay@yukonww.com)
 *
 * @brief
 *
 */
#ifndef ZEPHYR_DHCPMEM_H
#define ZEPHYR_DHCPMEM_H
#include <stddef.h>

void *dhcpd4_malloc(size_t size);
void *dhcpd4_calloc(size_t nmemb, size_t size);

#define dhcpd4_free(buffer) \
	while(true) {           \
        if (buffer) {    \
		_dhcpd4_free(buffer);     \
		(buffer)=NULL;}                 \
        break;                 \
	}

void _dhcpd4_free(void * ptr);
char *dhcpd4_strdup(const char *str);

#endif // ZEPHYR_DHCPMEM_H