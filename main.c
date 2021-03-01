#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <string.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>

#define IF_NAME "eth0"
#define ETH_TYPE 0xabba
#define MSG "Prvy ramec na AvS!!"
#define ARP_REQUEST 1
#define ARP_REPLY 2

struct ethHlavicka {
    uint8_t dstMAC[6];
    uint8_t srcMAC[6];
    uint16_t ethType;
    uint8_t payload[0];
}__attribute__((packed));

struct arpHlavicka {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t hardwareLength;
    uint8_t protocolLength;
    uint16_t opcode;
    uint8_t senderMAC[6];
    uint32_t senderIP;
    uint8_t targetMAC[6];
    uint32_t targetIP;
}__attribute__((packed));


int main() {
    int sock;
    struct sockaddr_ll addr;
    struct ethHlavicka *ramec;
    struct arpHlavicka *arp;

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sock == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    if((addr.sll_ifindex = if_nametoindex(IF_NAME)) == 0) {
        perror("if_nametoindex");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if(bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sock);
        exit(EXIT_FAILURE);
    }

    uint8_t *buffer;
    buffer = malloc(sizeof(struct ethHlavicka) + sizeof(struct arpHlavicka));
    if(buffer == 0) {
        printf("malloc");
        close(sock);
        exit(EXIT_FAILURE);
    }
    memset(buffer, 0, sizeof(struct ethHlavicka) + sizeof(struct arpHlavicka));

    ramec = (struct ethHlavicka *) buffer;
    ramec->dstMAC[0] = 0x01;
    ramec->dstMAC[1] = 0x02;
    ramec->dstMAC[2] = 0x03;
    ramec->dstMAC[3] = 0x04;
    ramec->dstMAC[4] = 0x05;
    ramec->dstMAC[5] = 0x06;

    ramec->srcMAC[0] = 0x08;
    ramec->srcMAC[1] = 0x00;
    ramec->srcMAC[2] = 0x27;
    ramec->srcMAC[3] = 0x57;
    ramec->srcMAC[4] = 0x91;
    ramec->srcMAC[5] = 0x21;
    ramec->ethType = htons(ETHERTYPE_ARP);

    arp = (struct arpHlavicka *) ramec->payload;
    arp->hardwareType = htons(1);
    arp->protocolType = htons(0x0800);
    arp->hardwareLength = 6;
    arp->protocolLength = 4;
    arp->opcode = htons(ARP_REQUEST);
    arp->senderMAC[0] = 0x08;
    arp->senderMAC[1] = 0x00;
    arp->senderMAC[2] = 0x27;
    arp->senderMAC[3] = 0x57;
    arp->senderMAC[4] = 0x91;
    arp->senderMAC[5] = 0x21;
    struct in_addr ip;
    if(inet_aton("192.168.88.27", &ip) == 0) {
        printf("error: inet_aton");
        close(sock);
        exit(EXIT_FAILURE);
    }
    arp->senderIP = ip.s_addr;
    char readIP[16];
    printf("Zadajte IP pre ARPping:");
    scanf("%s", readIP);
    if(inet_aton(readIP, &ip) == 0) {
        printf("error: inet_aton");
        close(sock);
        exit(EXIT_FAILURE);
    }
    arp->targetIP = ip.s_addr;

    if(write(sock, buffer, sizeof(struct ethHlavicka) + sizeof(struct arpHlavicka)) == -1) {
        perror("write");
    }

    uint8_t *readBuffer;
    readBuffer = malloc(sizeof(struct ethHlavicka) + sizeof(struct arpHlavicka));
    struct ethHlavicka *readRamec;
    struct arpHlavicka *readArp;
    readRamec = (struct ethHlavicka*) readBuffer;
    readArp = (struct arpHlavicka*) readRamec->payload;

    while(true) {
        if(read(sock, readBuffer, sizeof(struct ethHlavicka) + sizeof(struct arpHlavicka)) == -1) {
            perror("read");
        }

        if (readRamec->ethType == htons(ETHERTYPE_ARP) && readArp->protocolType == htons(0x0800) &&
        readArp->opcode == htons(ARP_REPLY) && memcmp(&arp->targetIP, &readArp->senderIP, 4) == 0) {
            printf("Response from %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
                   readArp->senderMAC[0],
                   readArp->senderMAC[1],
                   readArp->senderMAC[2],
                   readArp->senderMAC[3],
                   readArp->senderMAC[4],
                   readArp->senderMAC[5]);
            break;
        }
    }


    free(buffer);
    close(sock);
    return EXIT_SUCCESS;
}