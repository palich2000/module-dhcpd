#ifndef DHCPD_H
#define DHCPD_H
int dhcpd4_start(struct net_if *iface);
int dhcpd4_stop();
#endif