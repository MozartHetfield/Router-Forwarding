#include "include/sun_lib.h"

vector<int> mask_delimitators;
vector<rtable_entry> rtable_entries;

rtable_entry parse_single_rtable_entry(char* file_string) {
	rtable_entry entry;

	char *prefix, *next_hop, *mask, *interface;
	prefix = strtok(file_string, " ");
	next_hop = strtok(NULL, " ");
	mask = strtok(NULL, " ");
	interface = strtok(NULL, " ");

	inet_pton(AF_INET, prefix, &entry.prefix);
	inet_pton(AF_INET, next_hop, &entry.next_hop);
	inet_pton(AF_INET, mask, &entry.mask);
	entry.interface = atoi(interface);
	
	return entry;
}

void parse_rtable() {
	FILE* file = fopen("rtable.txt", "r");
	char* file_string = (char*) malloc(BUFFER_SIZE * sizeof(char));

	//O(n) for reading data
	while (fgets(file_string, BUFFER_SIZE, file) != NULL)
		rtable_entries.push_back(parse_single_rtable_entry(file_string));

	//O(nlogn) for sorting the vector by mask. if mask is the same, sort by prefix
	sort(rtable_entries.begin(), rtable_entries.end(), rtable_comparator);

	//O(n) to iterate through vector and find the delimitators. add them to mask_delimitators
	mask_delimitators.push_back(0); //we start at 0

	uint32_t iter_mask = -1;
	for (int i = 0; i < rtable_entries.size(); i++) {
		if (iter_mask == -1) //initialization step
			iter_mask = rtable_entries.at(i).mask;
		else if (iter_mask != rtable_entries.at(i).mask) {
			iter_mask = rtable_entries.at(i).mask;
			mask_delimitators.push_back(i);
		}
	}
	
	mask_delimitators.push_back(rtable_entries.size() - 1); //we stop at the end of the vector

	printf("[RTABLE PARSER] Successfully parsed %d entries.\n", rtable_entries.size());
}

rtable_entry* get_best_route(uint32_t ip) {
	rtable_entry* entry = NULL;
	int found_index = -1;

	//O(number of masks) = constant, smaller than 32
	for (int i = 0; i < mask_delimitators.size() - 1; i++) {
		int left = mask_delimitators.at(i);
		int right = mask_delimitators.at(i + 1);

		//O(logn) - binary search on the entries with the biggest mask
		found_index = binarySearch(left, right, ip);
		if (found_index != -1) {
			entry = &rtable_entries.at(found_index);
			break;
		}
	}

	/* //without optimization
	uint32_t latest_mask = 0;
	for (int i = 0; i < rtable_entries.size(); i++) {
		if (rtable_entries.at(i).prefix == (ip & rtable_entries.at(i).mask)) {
			if (rtable_entries.at(i).mask >= latest_mask) {
				latest_mask = rtable_entries.at(i).mask;
				entry = &rtable_entries.at(i);
			}
		}
	}
	*/

	return entry;
}

/* imported from lab4 */
uint16_t ip_checksum(void* vdata,size_t length) {
	char* data=(char*)vdata;

	uint64_t acc=0xffff;

	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	return htons(~acc);
}

int verify_check(struct iphdr* ip_hdr) {
		uint16_t prev_check = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t curr_check = ip_checksum(ip_hdr, sizeof(struct iphdr));
		if (curr_check != prev_check) {
			return -1;
		}
		return 1;
}

uint32_t get_router_ip(int interface) {
	char* char_ip = get_interface_ip(interface);
	uint32_t uint32_ip;
	inet_pton(AF_INET, char_ip, &uint32_ip);
	return uint32_ip;
}

uint32_t int_ip_from_4_char(u_char char_ip[4]) {
	char* beautiful_ip;
	sprintf(beautiful_ip, "%d.%d.%d.%d", char_ip[0], char_ip[1], char_ip[2], char_ip[3]);
	uint32_t uint32_ip;
	inet_pton(AF_INET, beautiful_ip, &uint32_ip);
	return uint32_ip;
}

void dec_ttl_and_update_check(struct iphdr* ip_hdr) {
	ip_hdr->ttl--;
	ip_hdr->check = 0;
	uint16_t new_check = ip_checksum(ip_hdr, sizeof(struct iphdr));
	ip_hdr->check = new_check;
}

bool rtable_comparator(const rtable_entry &first, const rtable_entry &second) {
    if (first.mask == second.mask)
    	return (first.prefix < second.prefix);
    return (first.mask > second.mask); //sort by mask, descending
}

int binarySearch(int l, int r, uint32_t value) { 
    if (r >= l) { 
        int mid = l + (r - l) / 2; 

        if ((value & rtable_entries.at(mid).mask) == rtable_entries.at(mid).prefix) 
            return mid; 
  
        if ((value & rtable_entries.at(mid).mask) < rtable_entries.at(mid).prefix)
            return binarySearch(l, mid - 1, value);
  
        return binarySearch(mid + 1, r, value); 
    } 

    return -1; 
} 

u_char* get_char_ip(uint32_t ip) {
	u_char* dest_ip = (u_char*) malloc(4 * sizeof(u_char));
	for (int j = 0; j < 4; j++) {
		dest_ip[j] = (ip >> j * 8) & 0xFF;
	}
	return dest_ip;
}