#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(dhcp4server, LOG_LEVEL_DBG);

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include "queue.h"
#include "options.h"
#include "logging.h"
#include "dhcpmem.h"
#include "zephyr/debug/stack.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wall"
#pragma GCC diagnostic error "-Wextra"
#pragma GCC diagnostic error "-Wunused"
#pragma GCC diagnostic error "-Wint-conversion"
#pragma GCC diagnostic error "-Wincompatible-pointer-types"

const uint8_t option_magic[4] = { 0x63, 0x82, 0x53, 0x63 };

/* 
 * Mapping table between DHCP options and 
 * functions that parse their value.
 */

static struct {

    char *name;
    int (*f) (char *, void **);

} dhcp_option_info [] = {

    [PAD] { "PAD", NULL },
    [END] { "END", NULL },
    [SUBNET_MASK] { "SUBNET_MASK", dhcpd4_parse_ip },
    [TIME_OFFSET] { "TIME_OFFSET", dhcpd4_parse_long },
    [ROUTER] { "ROUTER", dhcpd4_parse_ip_list },
    [TIME_SERVER] { "TIME_SERVER", dhcpd4_parse_ip_list },
    [NAME_SERVER] { "NAME_SERVER", dhcpd4_parse_ip_list },
    [DOMAIN_NAME_SERVER] { "DOMAIN_NAME_SERVER", dhcpd4_parse_ip_list },
    [LOG_SERVER] { "LOG_SERVER", dhcpd4_parse_ip_list },
    [COOKIE_SERVER] { "COOKIE_SERVER", dhcpd4_parse_ip_list },
    [LPR_SERVER] { "LPR_SERVER", dhcpd4_parse_ip_list },
    [IMPRESS_SERVER] { "IMPRESS_SERVER", dhcpd4_parse_ip_list },
    [RESOURCE_LOCATION_SERVER] { "RESOURCE_LOCATION_SERVER", dhcpd4_parse_ip_list },
    [HOST_NAME] { "HOST_NAME", dhcpd4_parse_string },
    [BOOT_FILE_SIZE] { "BOOT_FILE_SIZE", dhcpd4_parse_short },
    [MERIT_DUMP_FILE] { "MERIT_DUMP_FILE", dhcpd4_parse_string },
    [DOMAIN_NAME] { "DOMAIN_NAME", dhcpd4_parse_string },
    [SWAP_SERVER] { "SWAP_SERVER", dhcpd4_parse_ip },
    [ROOT_PATH] { "ROOT_PATH", dhcpd4_parse_string },
    [EXTENSIONS_PATH] { "EXTENSIONS_PATH", dhcpd4_parse_string },
    [IP_FORWARDING] { "IP_FORWARDING", dhcpd4_parse_byte },
    [NON_LOCAL_SOURCE_ROUTING] { "NON_LOCAL_SOURCE_ROUTING", dhcpd4_parse_byte },
    [POLICY_FILTER] { "POLICY_FILTER", dhcpd4_parse_ip_list },
    [MAXIMUM_DATAGRAM_REASSEMBLY_SIZE] { "MAXIMUM_DATAGRAM_REASSEMBLY_SIZE", dhcpd4_parse_short
	},
    [DEFAULT_IP_TIME_TO_LIVE] { "DEFAULT_IP_TIME_TO_LIVE", dhcpd4_parse_byte },
    [PATH_MTU_AGING_TIMEOUT] { "PATH_MTU_AGING_TIMEOUT", dhcpd4_parse_long },
    [PATH_MTU_PLATEAU_TABLE] { "PATH_MTU_PLATEAU_TABLE", dhcpd4_parse_short_list },
    [INTERFACE_MTU] { "INTERFACE_MTU", dhcpd4_parse_short },
    [ALL_SUBNETS_ARE_LOCAL] { "ALL_SUBNETS_ARE_LOCAL", dhcpd4_parse_byte },
    [BROADCAST_ADDRESS] { "BROADCAST_ADDRESS", dhcpd4_parse_ip },
    [PERFORM_MASK_DISCOVERY] { "PERFORM_MASK_DISCOVERY", dhcpd4_parse_byte },
    [MASK_SUPPLIER] { "MASK_SUPPLIER", dhcpd4_parse_byte },
    [PERFORM_ROUTER_DISCOVERY] { "PERFORM_ROUTER_DISCOVERY", dhcpd4_parse_byte },
    [ROUTER_SOLICITATION_ADDRESS] { "ROUTER_SOLICITATION_ADDRESS", dhcpd4_parse_ip },
    [STATIC_ROUTE] { "STATIC_ROUTE", dhcpd4_parse_ip_list },
    [TRAILER_ENCAPSULATION] { "TRAILER_ENCAPSULATION", dhcpd4_parse_byte },
    [ARP_CACHE_TIMEOUT] { "ARP_CACHE_TIMEOUT", dhcpd4_parse_long },
    [ETHERNET_ENCAPSULATION] { "ETHERNET_ENCAPSULATION", dhcpd4_parse_byte },
    [TCP_DEFAULT_TTL] { "TCP_DEFAULT_TTL", dhcpd4_parse_byte },
    [TCP_KEEPALIVE_INTERVAL] { "TCP_KEEPALIVE_INTERVAL", dhcpd4_parse_long },
    [TCP_KEEPALIVE_GARBAGE] { "TCP_KEEPALIVE_GARBAGE", dhcpd4_parse_byte },
    [NETWORK_INFORMATION_SERVICE_DOMAIN] { "NETWORK_INFORMATION_SERVICE_DOMAIN", dhcpd4_parse_string
	},
    [NETWORK_INFORMATION_SERVERS] { "NETWORK_INFORMATION_SERVERS", dhcpd4_parse_ip_list },
    [NETWORK_TIME_PROTOCOL_SERVERS] { "NETWORK_TIME_PROTOCOL_SERVERS", dhcpd4_parse_ip_list },
    [VENDOR_SPECIFIC_INFORMATION] { "VENDOR_SPECIFIC_INFORMATION", dhcpd4_parse_byte_list },
    [NETBIOS_OVER_TCP_IP_NAME_SERVER] { "NETBIOS_OVER_TCP_IP_NAME_SERVER", dhcpd4_parse_ip_list
	},
    //[NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER] { "NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER", parse_ip_list },
    [NETBIOS_OVER_TCP_IP_NODE_TYPE] { "NETBIOS_OVER_TCP_IP_NODE_TYPE", dhcpd4_parse_byte },
    [NETBIOS_OVER_TCP_IP_SCOPE] { "NETBIOS_OVER_TCP_IP_SCOPE", dhcpd4_parse_string },
    [X_WINDOW_SYSTEM_FONT_SERVER] { "X_WINDOW_SYSTEM_FONT_SERVER", dhcpd4_parse_ip_list },
    [X_WINDOW_SYSTEM_DISPLAY_MANAGER] { "X_WINDOW_SYSTEM_DISPLAY_MANAGER", dhcpd4_parse_ip_list
	},
    [NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN] { "NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN", dhcpd4_parse_string
	},
    [NETWORK_INFORMATION_SERVICE_PLUS_SERVERS] { "NETWORK_INFORMATION_SERVICE_PLUS_SERVERS", dhcpd4_parse_ip_list
	},
    [MOBILE_IP_HOME_AGENT] { "MOBILE_IP_HOME_AGENT", dhcpd4_parse_ip_list },
    [SMTP_SERVER] { "SMTP_SERVER", dhcpd4_parse_ip_list },
    [POP3_SERVER] { "POP3_SERVER", dhcpd4_parse_ip_list },
    [NNTP_SERVER] { "NNTP_SERVER", dhcpd4_parse_ip_list },
    [DEFAULT_WWW_SERVER] { "DEFAULT_WWW_SERVER", dhcpd4_parse_ip_list },
    [DEFAULT_FINGER_SERVER] { "DEFAULT_FINGER_SERVER", dhcpd4_parse_ip_list },
    [DEFAULT_IRC_SERVER] { "DEFAULT_IRC_SERVER", dhcpd4_parse_ip_list },
    [STREETTALK_SERVER] { "STREETTALK_SERVER", dhcpd4_parse_ip_list },
    [STREETTALK_DIRECTORY_ASSISTANCE_SERVER] { "STREETTALK_DIRECTORY_ASSISTANCE_SERVER", dhcpd4_parse_ip_list
	},
    [REQUESTED_IP_ADDRESS] { "REQUESTED_IP_ADDRESS", NULL },
    [IP_ADDRESS_LEASE_TIME] { "IP_ADDRESS_LEASE_TIME", dhcpd4_parse_long },
    [OPTION_OVERLOAD] { "OPTION_OVERLOAD", dhcpd4_parse_byte },
    [TFTP_SERVER_NAME] { "TFTP_SERVER_NAME", dhcpd4_parse_string },
    [BOOTFILE_NAME] { "BOOTFILE_NAME", dhcpd4_parse_string },
    [DHCP_MESSAGE_TYPE] { "DHCP_MESSAGE_TYPE", NULL },
    [SERVER_IDENTIFIER] { "SERVER_IDENTIFIER", dhcpd4_parse_ip },
    [PARAMETER_REQUEST_LIST] { "PARAMETER_REQUEST_LIST", NULL },
    [MESSAGE] { "MESSAGE", NULL },
    [MAXIMUM_DHCP_MESSAGE_SIZE] { "MAXIMUM_DHCP_MESSAGE_SIZE", NULL },
    [RENEWAL_T1_TIME_VALUE] { "RENEWAL_T1_TIME_VALUE", dhcpd4_parse_long },
    [REBINDING_T2_TIME_VALUE] { "REBINDING_T2_TIME_VALUE", dhcpd4_parse_long },
    [VENDOR_CLASS_IDENTIFIER] { "VENDOR_CLASS_IDENTIFIER", NULL },
    [CLIENT_IDENTIFIER] { "CLIENT_IDENTIFIER", NULL },
    
};

/* Value parsing functions */

int
dhcpd4_parse_byte (char *s, void **p)
{
    *p = dhcpd4_malloc(sizeof(uint8_t));
    uint8_t n = ((uint8_t) strtol(s, NULL, 0));
    memcpy(*p, &n, sizeof(n));
    
    return sizeof(uint8_t);
}

int dhcpd4_parse_byte_list(char *s, void **p)
{
    *p = dhcpd4_malloc(strlen(s) * sizeof(uint8_t)); // slightly over the strictly requested size

    int count = 0;
    char *save_ptr =NULL;
    char *s2 = dhcpd4_strdup(s);
    char *s3 = strtok_r(s2, ", ", &save_ptr);

    while(s3 != NULL) {

	uint8_t n = ((uint8_t) strtol(s3, NULL, 0));

	memcpy(((uint8_t *) *p) + count, &n, sizeof(uint8_t));

	count += sizeof(uint8_t);
	s3 = strtok_r(NULL, " ",&save_ptr);
    }

    dhcpd4_free(s2);

    return count;
}

int dhcpd4_parse_short(char *s, void **p)
{
    *p = dhcpd4_malloc(sizeof(uint16_t));
    uint16_t n = ((uint16_t) strtol(s, NULL, 0));
    memcpy(*p, &n, sizeof(n));
    
    return sizeof(uint16_t);
}

int dhcpd4_parse_short_list(char *s, void **p)
{
    *p = dhcpd4_malloc(strlen(s) * sizeof(uint16_t)); // slightly over the strictly requested size

    int count = 0;
    char *save_ptr =NULL;
    char *s2 = dhcpd4_strdup(s);
    char *s3 = strtok_r(s2, ", ",&save_ptr);

    while(s3 != NULL) {

	uint16_t n = ((uint16_t) strtol(s3, NULL, 0));

	memcpy(((uint8_t *) *p) + count, &n, sizeof(uint16_t));

	count += sizeof(uint16_t);
	s3 = strtok_r(NULL, " ",&save_ptr);
    }

    dhcpd4_free(s2);

    return count;
}

int dhcpd4_parse_long(char *s, void **p)
{
    *p = dhcpd4_malloc(sizeof(uint32_t));
    uint32_t n = strtol(s, NULL, 0);
    memcpy(*p, &n, sizeof(n));

    return sizeof(uint32_t);
}

int dhcpd4_parse_string(char *s, void **p)
{
    *p = dhcpd4_strdup(s);

    return strlen(s);
}

int dhcpd4_parse_ip(char *s, void **p)
{
    struct sockaddr_in ip;
    *p = dhcpd4_malloc(sizeof(uint32_t));
    if (*p==NULL) {
	LOG_ERR("Out of memory");
	return 0;
    }
    if (inet_pton(AF_INET,s, &ip.sin_addr) == 0) { // error: invalid IP address
	dhcpd4_free(*p);
	return 0;
    }

    memcpy(*p, &ip.sin_addr, sizeof(uint32_t));
    log_stack_usage(k_current_get());
    return sizeof(uint32_t);
}

int dhcpd4_parse_ip_list(char *s, void **p)
{
    *p = dhcpd4_malloc(strlen(s) * sizeof(uint32_t) /
		       4); // slightly over the strictly required size

    int count = 0;
    char *save_ptr =NULL;
    char *s2 = dhcpd4_strdup(s);
    char *s3 = strtok_r(s2, ", ", &save_ptr);

    while(s3 != NULL) {
	struct sockaddr_in ip;

	if (inet_pton(AF_INET,s3, &ip.sin_addr) == 0) { // error: invalid IP address
		dhcpd4_free(*p);
	    return 0;
	}

	memcpy(((uint8_t *) *p) + count, &ip.sin_addr, sizeof(uint32_t));

	count += sizeof(uint32_t);
	s3 = strtok_r(NULL, " ",&save_ptr);
    }

    dhcpd4_free(s2);

    return count;
}

int dhcpd4_parse_mac(char *s, void **p)
{
    *p = dhcpd4_malloc(6);
    int i;

    if (strlen(s) != 17 ||
       s[2] != ':' || s[5] != ':' || s[8] != ':' || s[11] != ':' || s[14] != ':') {
	dhcpd4_free(*p);
	return 0; // error: invalid MAC address
    }

    if (!isxdigit(s[0]) || !isxdigit(s[1]) || !isxdigit(s[3]) || !isxdigit(s[4]) || 
	!isxdigit(s[6]) || !isxdigit(s[7]) || !isxdigit(s[9]) || !isxdigit(s[10]) ||
	!isxdigit(s[12]) || !isxdigit(s[13]) || !isxdigit(s[15]) || !isxdigit(s[16])) {
	dhcpd4_free(*p);
	return 0; // error: invalid MAC address
    }

    for (i = 0; i < 6; i++) {
	long b = strtol(s+(3*i), NULL, 16);
	((uint8_t *) *p)[i] = (uint8_t) b;
    }

    return 6;
}

/* Option-related functions */

/* 
 * Given the name of the option and its value as strings,
 * fill the dhcp_option structure pointed by opt.
 *
 * On success return the parsed option id,
 * otherwise return zero.
 */
uint8_t dhcpd4_parse_option(dhcp_option *option, char *name, char *value)
{
    int (*f) (char *, void **);
    int id;

    if (!name) {
	LOG_ERR("name is NULL ");
	return 0;
    }

    if (!option || !value) {
	LOG_ERR("value or opt is NULL option %s", name);
	return 0;
    }

    uint8_t len;
    uint8_t *p;

    for (id = 0; id < 256; id++) { // search the option by name
        if (dhcp_option_info[id].name &&
                strcmp(dhcp_option_info[id].name, name) == 0) break;
    }

    if (id == 256) { // not found
        log_error("Unsupported DHCP option '%s'", name);
        return 0;
    }

    f = dhcp_option_info[id].f;

    if (f == NULL) { // no parsing function available
        log_error("Unsupported DHCP option '%s'", name);
        return 0;
    }

    len = f(value, (void **)&p); // parse the value

    if(len == 0) // error parsing the value
	return 0;

    // structure filling
    option->id = id;
    option->len = len;
    memcpy(option->data, p, len);

    dhcpd4_free(p);

    return option->id;
}

/*
 * Initialize an option list.
 */

void dhcpd4_init_option_list(dhcp_option_list *list)
{
    TAILQ_INIT(list);
}

/*
 * Given a list of options search an option having
 * the passed option id, and returns a pointer to it.
 *
 * If the option is not present the function returns NULL.
 */

dhcp_option *dhcpd4_search_option(dhcp_option_list *list, uint8_t id)
{
    dhcp_option *opt, *opt_temp;

    TAILQ_FOREACH_SAFE(opt, list, pointers, opt_temp) {

	if(opt->id == id)
	    return opt;

    }
    
    return NULL;
}

/*
 * Print options in list.
 */

void dhcpd4_print_options(dhcp_option_list *list)
{
    dhcp_option *opt, *opt_temp;
    int i=0;

    TAILQ_FOREACH_SAFE(opt, list, pointers, opt_temp) {

	printf("options[%d]=%d (%s)\n", i++, opt->id,
	       dhcp_option_info[opt->id].name);

    }
}


/*
 * Append the provided option to the list.
 *
 * Always allocate new memory, that must be freed later...
 */

int dhcpd4_append_option(dhcp_option_list *list, dhcp_option *opt)
{
    dhcp_option *nopt = dhcpd4_calloc(1, sizeof(*nopt));
    if (!nopt) {
	LOG_ERR("[%s] Out of memory", __FUNCTION__ );
	return -1;
    }
    memcpy(nopt, opt, 2 + opt->len);
    
    TAILQ_INSERT_TAIL(list, nopt, pointers);
    return 0;
}

/*
 * Parse the options contained in a DHCP message into a list.
 *
 * Return 1 on success, 0 if the options are malformed.
 */

int dhcpd4_parse_options_to_list(dhcp_option_list *list, dhcp_option *opts, size_t len)
{
    dhcp_option *opt, *end;

    opt = opts;
    end = (dhcp_option *)(((uint8_t *)opts) + len);

    if (len < 4 ||
	memcmp(opt, option_magic, sizeof(option_magic)) != 0)
	return 0;

    opt = (dhcp_option *)(((uint8_t *) opt) + 4);

    while (opt < end  &&
	   opt->id != END) { // TODO: check also valid option sizes

	if ((dhcp_option *)(((uint8_t *) opt) + 2 + opt->len) >= end)
	    return 0; // the len field is too long

	dhcpd4_append_option(list, opt);

        opt = (dhcp_option *)(((uint8_t *) opt) + 2 + opt->len);
    }

    if (opt < end && opt->id == END)
        return 1;

    return 0;
}

/*
 * Serialize a list of options, to be inserted directly inside
 * the options section of a DHCP message.
 *
 * Return 0 on error, the total serialized len on success.
 */

size_t dhcpd4_serialize_option_list(dhcp_option_list *list, uint8_t *buf, size_t len)
{
    uint8_t *p = buf;

    if (len < 4)
	return 0;

    memcpy(p, option_magic, sizeof(option_magic));
    p += 4; len -= 4;

    dhcp_option *opt, *opt_temp;
    
    TAILQ_FOREACH_SAFE(opt, list, pointers, opt_temp) {

	if (len <= 2 + (size_t)opt->len)
	    return 0;

	memcpy(p, opt, 2 + opt->len);
	p   += 2 + opt->len;
	len -= 2 + opt->len;
	
    }

    if (len < 1)
	return 0;

    *p = END;

    p++; len--;

    return p - buf;
}

/*
 * Delete an option list and deallocate its memory.
 * Deallocate even the list elements.
 */

void dhcpd4_delete_option_list(dhcp_option_list *list)
{
    dhcp_option *opt = TAILQ_FIRST(list);
    dhcp_option *tmp;
    
    while (opt != NULL) {
	tmp = TAILQ_NEXT(opt, pointers);
	dhcpd4_option_free(&opt);
	opt = tmp;
     }
    
    TAILQ_INIT(list);
}

void dhcpd4_option_free(dhcp_option ** option) {
    if (option==NULL || *option==NULL )
	return ;
    dhcpd4_free(*option);
}