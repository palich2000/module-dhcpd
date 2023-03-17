/**
 * @file dhcpmem.c
 * @author Tsaplay Yuriy (y.tsaplay@yukonww.com)
 *
 * @brief
 *
 */
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>

#include "dhcpmem.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wall"
#pragma GCC diagnostic error "-Wextra"
#pragma GCC diagnostic error "-Wunused"
#pragma GCC diagnostic error "-Wint-conversion"
#pragma GCC diagnostic error "-Wincompatible-pointer-types"

#define DHCP4_SERVER_BUFFER_SIZE (4096u*2u)

static K_HEAP_DEFINE(dhcp4_server_mem_buffer, DHCP4_SERVER_BUFFER_SIZE);
static K_MUTEX_DEFINE(dhcp4_server_mem_mutex);

void *dhcpd4_malloc(size_t size){
	k_mutex_lock(&dhcp4_server_mem_mutex, K_FOREVER);
	void * buffer = k_heap_alloc(&dhcp4_server_mem_buffer, size, K_NO_WAIT);
	if (!buffer) {
		printk("out of memory dhcpd4_malloc");
	}
	k_mutex_unlock(&dhcp4_server_mem_mutex);
	return buffer;
}

void *dhcpd4_calloc(size_t nmemb, size_t size)
{
	size = size * nmemb;
	void *ret = dhcpd4_malloc(size);

	if (ret != NULL) {
		(void)memset(ret, 0, size);
	} else {
		printk("out of memory dhcpd4_calloc");
	}
	return ret;
}

void _dhcpd4_free(void * ptr) {
	if (ptr) {
		k_mutex_lock(&dhcp4_server_mem_mutex, K_FOREVER);
		k_heap_free(&dhcp4_server_mem_buffer, ptr);
		k_mutex_unlock(&dhcp4_server_mem_mutex);
	}
}

char *dhcpd4_strdup(const char *str){
	if(str) {
		size_t l = strlen(str);
		char * buf = dhcpd4_malloc(l + 1);
		if (buf) {
			memmove(buf, str, l);
			buf[l] = 0;
		}
		return buf;
	} else {
		return NULL;
	}
}