#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdint.h>
#include <time.h>

#include "queue.h"

/*
 * Code ID of DHCP and BOOTP options 
 * as defined in RFC 2132
 */

enum dhcpd_msg_type {
     DHCP_DISCOVER = 1,
     DHCP_OFFER    = 2,
     DHCP_REQUEST  = 3,
     DHCP_DECLINE  = 4,
     DHCP_ACK      = 5,
     DHCP_NAK      = 6,
     DHCP_RELEASE  = 7,
     DHCP_INFORM   = 8,
};

enum {

/* RFC 1497 Vendor Extensions */

    PAD = 0,
    END = 255,

    SUBNET_MASK = 1,
    TIME_OFFSET = 2,
    ROUTER = 3,
    TIME_SERVER = 4,
    NAME_SERVER = 5,
    DOMAIN_NAME_SERVER = 6,
    LOG_SERVER = 7,
    COOKIE_SERVER = 8,
    LPR_SERVER = 9,
    IMPRESS_SERVER = 10,
    RESOURCE_LOCATION_SERVER = 11,
    HOST_NAME = 12,
    BOOT_FILE_SIZE = 13,
    MERIT_DUMP_FILE = 14,
    DOMAIN_NAME = 15,
    SWAP_SERVER = 16,
    ROOT_PATH = 17,
    EXTENSIONS_PATH = 18,

/* IP Layer Parameters per Host */

    IP_FORWARDING = 19,
    NON_LOCAL_SOURCE_ROUTING = 20,
    POLICY_FILTER = 21,
    MAXIMUM_DATAGRAM_REASSEMBLY_SIZE = 22,
    DEFAULT_IP_TIME_TO_LIVE = 23,
    PATH_MTU_AGING_TIMEOUT = 24,
    PATH_MTU_PLATEAU_TABLE = 25,

/* IP Layer Parameters per Interface */

    INTERFACE_MTU = 26,
    ALL_SUBNETS_ARE_LOCAL = 27,
    BROADCAST_ADDRESS = 28,
    PERFORM_MASK_DISCOVERY = 29,
    MASK_SUPPLIER = 30,
    PERFORM_ROUTER_DISCOVERY = 31,
    ROUTER_SOLICITATION_ADDRESS = 32,
    STATIC_ROUTE = 33,

/* Link Layer Parameters per Interface */

    TRAILER_ENCAPSULATION = 34,
    ARP_CACHE_TIMEOUT = 35,
    ETHERNET_ENCAPSULATION = 36,

/* TCP Parameters */

    TCP_DEFAULT_TTL = 37,
    TCP_KEEPALIVE_INTERVAL = 38,
    TCP_KEEPALIVE_GARBAGE = 39,

/* Application and Service Parameters */

    NETWORK_INFORMATION_SERVICE_DOMAIN = 40,
    NETWORK_INFORMATION_SERVERS = 41,
    NETWORK_TIME_PROTOCOL_SERVERS = 42,
    VENDOR_SPECIFIC_INFORMATION = 43,
    NETBIOS_OVER_TCP_IP_NAME_SERVER = 44,
    NETBIOS_OVER_TCP_IP_DATAGRAM_DISTRIBUTION_SERVER = 4,
    NETBIOS_OVER_TCP_IP_NODE_TYPE = 46,
    NETBIOS_OVER_TCP_IP_SCOPE = 47,
    X_WINDOW_SYSTEM_FONT_SERVER = 48,
    X_WINDOW_SYSTEM_DISPLAY_MANAGER = 49,
    NETWORK_INFORMATION_SERVICE_PLUS_DOMAIN = 64,
    NETWORK_INFORMATION_SERVICE_PLUS_SERVERS = 65,
    MOBILE_IP_HOME_AGENT = 68,
    SMTP_SERVER = 69,
    POP3_SERVER = 70,
    NNTP_SERVER = 71,
    DEFAULT_WWW_SERVER = 72,
    DEFAULT_FINGER_SERVER = 73,
    DEFAULT_IRC_SERVER = 74,
    STREETTALK_SERVER = 75,
    STREETTALK_DIRECTORY_ASSISTANCE_SERVER = 76,

/* DHCP Extensions */

    REQUESTED_IP_ADDRESS = 50,
    IP_ADDRESS_LEASE_TIME = 51,
    OPTION_OVERLOAD = 52,
    TFTP_SERVER_NAME = 66,
    BOOTFILE_NAME = 67,
    DHCP_MESSAGE_TYPE = 53,
    SERVER_IDENTIFIER = 54,
    PARAMETER_REQUEST_LIST = 55,
    MESSAGE = 56,
    MAXIMUM_DHCP_MESSAGE_SIZE = 57,
    RENEWAL_T1_TIME_VALUE = 58,
    REBINDING_T2_TIME_VALUE = 59,
    VENDOR_CLASS_IDENTIFIER = 60,
    CLIENT_IDENTIFIER = 61

};

struct dhcp_option {
    uint8_t id;        // option id
    uint8_t len;       // option length
    uint8_t data[256]; // option data

    TAILQ_ENTRY(dhcp_option) pointers; // pointers, see queue(3)
};

typedef struct dhcp_option dhcp_option;

typedef TAILQ_HEAD(dhcp_option_list_, dhcp_option) DHCP_OPTION_LIST;
typedef struct dhcp_option_list_ dhcp_option_list;

/* Value parsing functions:
 *
 * Parse the string pointed by s, and allocate the
 * pointer p to contain the parsed data.
 * 
 * On success return the size of the parsed data,
 * on error return zero.
 */

int dhcpd4_parse_byte(char *s, void **p);
int dhcpd4_parse_byte_list(char *s, void **p);
int dhcpd4_parse_short(char *s, void **p);
int dhcpd4_parse_short_list(char *s, void **p);
int dhcpd4_parse_long(char *s, void **p);
int dhcpd4_parse_string(char *s, void **p);
int dhcpd4_parse_ip(char *s, void **p);
int dhcpd4_parse_ip_list(char *s, void **p);
int dhcpd4_parse_mac(char *s, void **p);

/* Other prototypes */

void dhcpd4_init_option_list(dhcp_option_list *list);
uint8_t dhcpd4_parse_option(dhcp_option *option, char *name, char *value);
dhcp_option *dhcpd4_search_option(dhcp_option_list *list, uint8_t id);
void dhcpd4_print_options(dhcp_option_list *list);
int dhcpd4_append_option(dhcp_option_list *list, dhcp_option *opt);
void dhcpd4_option_free(dhcp_option ** option);
int dhcpd4_parse_options_to_list(dhcp_option_list *list, dhcp_option *opts, size_t len);
size_t dhcpd4_serialize_option_list(dhcp_option_list *list, uint8_t *buf, size_t len);
void dhcpd4_delete_option_list(dhcp_option_list *list);

#endif