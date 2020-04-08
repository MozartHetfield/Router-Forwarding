#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <vector> 
#include <queue>
#include <algorithm>
#include "skel.h"

using namespace std;

#define BUFFER_SIZE    100
#define NEW_TTL_VALUE  64
#define ARP_PACKET_LEN 44

typedef struct rtable_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} rtable_entry;

typedef struct arp_header {
	uint8_t smac[6];
	uint8_t dmac[6];
	__u32 sip;
	__u32 dip;
	int type;
} arp_header;

rtable_entry parse_single_rtable_entry(char* file_string);

void parse_rtable();

rtable_entry* get_best_route(uint32_t ip);

bool rtable_comparator(const rtable_entry &first, const rtable_entry &second);

int binarySearch(int l, int r, uint32_t value);

/* imported from lab4 */
uint16_t ip_checksum(void* vdata,size_t length);

int verify_check(struct iphdr* ip_hdr);

uint32_t get_router_ip(int interface);

void dec_ttl_and_update_check(struct iphdr* ip_hdr);

u_char* get_char_ip(uint32_t ip);

uint32_t int_ip_from_4_char(u_char char_ip[4]);