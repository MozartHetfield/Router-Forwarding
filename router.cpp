#include "include/sun_lib.h"
#include <iostream>

using namespace std;

typedef struct arp_entry {
	uint32_t ip;
	u_char mac[6];
} arp_entry;

vector<arp_entry*> arp_vec;

arp_entry* get_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_vec.size(); i++) {
		if (arp_vec.at(i)->ip == ip)
			return arp_vec.at(i);
	}
	return NULL;
}

bool update_mac_addresses(uint32_t destination_ip, struct ether_header *eth_hdr, rtable_entry* best_route) {
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);

	arp_entry* d_entry = get_arp_entry(destination_ip);

	if (d_entry == NULL) {
		printf("No MAC found. Processing ARP Request\n");
		packet arp_req;
		struct ether_header *eth_hdr_req = (struct ether_header*) arp_req.payload;
		struct ether_arp *arp_hdr_req = (struct ether_arp *)(arp_req.payload + FIRST_OFF);

		arp_req.interface = best_route->interface;

		/* eth header */
		char* broadcast = "ff:ff:ff:ff:ff:ff";

		hwaddr_aton(broadcast, eth_hdr_req->ether_dhost);
		get_interface_mac(best_route->interface, eth_hdr_req->ether_shost);
		eth_hdr_req->ether_type = ntohs(ETHERTYPE_ARP);

		/* arp header */
		arp_hdr_req->ea_hdr.ar_op = ntohs(ARPOP_REQUEST);
		arp_hdr_req->ea_hdr.ar_hrd = ntohs(1);
		arp_hdr_req->ea_hdr.ar_pro = htons(0x800);
		arp_hdr_req->ea_hdr.ar_hln = 6;
		arp_hdr_req->ea_hdr.ar_pln = 4;

		memcpy(arp_hdr_req->arp_sha, eth_hdr_req->ether_shost, 6);
 
		char* none_target = "00:00:00:00:00:00";
		hwaddr_aton(none_target, arp_hdr_req->arp_tha);

		u_char* router_ip_on_this_interface;
		router_ip_on_this_interface = (u_char*) get_interface_ip(arp_req.interface);
		memcpy(arp_hdr_req->arp_spa, router_ip_on_this_interface, 4);

		u_char* next_hop_ip;
		next_hop_ip = get_char_ip(best_route->next_hop);
		memcpy(arp_hdr_req->arp_tpa, next_hop_ip, 4);
		free(next_hop_ip);

		arp_req.len = ARP_PACKET_LEN; //seen from wireshark :D
		int send = send_packet(arp_req.interface, &arp_req);
		DIE(send == 0, "send_arp_request");
		return false;
	}

	for (int i = 0; i < 6; i++)
			eth_hdr->ether_dhost[i] = (u_char) d_entry->mac[i];

	return true;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	rtable_entry* best_route;

	init();
	parse_rtable();

	queue<packet> q;
	bool validation;

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header*) m.payload;
		u_short	header_type = ntohs(eth_hdr->ether_type);

		if (header_type == ETHERTYPE_IP) {
			printf("Received IP\n");
			/* define headers */
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + FIRST_OFF);
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + SECOND_OFF);
			
			uint32_t router_ip = get_router_ip(m.interface);
			best_route = get_best_route(ip_hdr->daddr);

			if (ip_hdr->daddr == router_ip) {
				if (icmp_hdr->type == ICMP_ECHO)
				{
					printf("Router received ECHO_REQUEST\n");
					
					if (ip_hdr->ttl <= 1) {
						icmp_hdr->type = ICMP_TIME_EXCEEDED;
					 	icmp_hdr->code = ICMP_NET_UNREACH;

					 	if (!verify_check(ip_hdr))
							continue;

						ip_hdr->ttl = NEW_TTL_VALUE;
						dec_ttl_and_update_check(ip_hdr);

						validation = update_mac_addresses(ip_hdr->saddr, eth_hdr, best_route);

						if (validation) {
							int send = send_packet(best_route->interface, &m);
							DIE(send == 0, "send_packet");
						} else {
							q.push(m);
						}
						continue;
					}

					if (!verify_check(ip_hdr))
						continue;

					icmp_hdr->type = ICMP_ECHOREPLY;
					ip_hdr->ttl = NEW_TTL_VALUE;

					ip_hdr->daddr = ip_hdr->saddr;
					ip_hdr->saddr = router_ip;

					dec_ttl_and_update_check(ip_hdr);

					u_char router_mac_on_this_interface[6];
					get_interface_mac(m.interface, router_mac_on_this_interface);
					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
					memcpy(eth_hdr->ether_shost, router_mac_on_this_interface, 6);

					int send = send_packet(m.interface, &m);
					DIE(send == 0, "send_packet");

					// if (validation) {
					// 	int send = send_packet(m.interface, &m);
					// 	DIE(send == 0, "send_packet");
					// } else {
					// 	q.push(m);
					// }
					continue;
				}
				else
					continue;
			} else if (ip_hdr->ttl <= 1 || best_route == NULL) {
				best_route = get_best_route(ip_hdr->saddr);

				if (best_route == NULL)
				 	continue;

				if (ip_hdr->ttl > 1)
				{
					icmp_hdr->type = ICMP_DEST_UNREACH;
					icmp_hdr->code = ICMP_NET_UNREACH;
				} else {
					icmp_hdr->type = ICMP_TIME_EXCEEDED;
					icmp_hdr->code = ICMP_NET_UNREACH;
				}

				ip_hdr->ttl = NEW_TTL_VALUE;
				
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = router_ip;

				dec_ttl_and_update_check(ip_hdr);

				icmp_hdr->checksum = 0;
				icmp_hdr->un.echo.sequence++;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

				u_char router_mac_on_this_interface[6];
				get_interface_mac(m.interface, router_mac_on_this_interface);
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr->ether_shost, router_mac_on_this_interface, 6);

				int send = send_packet(m.interface, &m);
				DIE(send == 0, "send_packet");

				// validation = update_mac_addresses(best_route->next_hop, eth_hdr, best_route); //AICI ERA IP_S
				// if (validation) {
				// 	printf("Sent Time Exceeded or Destination Unreachable\n");
				// 	int send = send_packet(best_route->interface, &m);
				// 	DIE(send == 0, "send_packet");
				// } else {
				// 	q.push(m);
				// }
				// continue;
			}
			if (!verify_check(ip_hdr))
				continue;

			dec_ttl_and_update_check(ip_hdr);

			validation = update_mac_addresses(ip_hdr->daddr, eth_hdr, best_route);
			if (validation) {
				int send = send_packet(best_route->interface, &m);
				DIE(send == 0, "send_packet");
			} else {
				q.push(m);
			}
			
		} else if (header_type == ETHERTYPE_ARP) {
			printf("Received ARP: ");
			struct ether_arp *arp_hdr = (struct ether_arp *)(m.payload + FIRST_OFF);
			u_short arp_header_type = ntohs(arp_hdr->ea_hdr.ar_op);

			if (arp_header_type == ARPOP_REQUEST) {
				printf("Request\n");

				u_char router_mac_on_this_interface[6];
				get_interface_mac(m.interface, router_mac_on_this_interface);
				uint32_t router_ip_on_this_interface_int = get_router_ip(m.interface);
				u_char* router_ip_on_this_interface_char = get_char_ip(router_ip_on_this_interface_int);

				/* complete ether header */
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr->ether_shost, router_mac_on_this_interface, 6);

				/* complete arp header */
				arp_hdr->ea_hdr.ar_op = ntohs(ARPOP_REPLY);

				memcpy(arp_hdr->arp_tha, arp_hdr->arp_sha, 6);
				memcpy(arp_hdr->arp_sha, router_mac_on_this_interface, 6);
				memcpy(arp_hdr->arp_tpa, arp_hdr->arp_spa, 4);
				memcpy(arp_hdr->arp_spa, router_ip_on_this_interface_char, 4);

				int send = send_packet(m.interface, &m);
				DIE(send == 0, "send_packet");
			} else if (arp_header_type == ARPOP_REPLY) {
				printf("Reply\n");

				arp_entry* requested_entry = (arp_entry*) malloc(sizeof(arp_entry));
				requested_entry->ip = int_ip_from_4_char(arp_hdr->arp_spa);
				memcpy(requested_entry->mac, arp_hdr->arp_sha, 6);
				arp_vec.push_back(requested_entry);

				if (q.size() != 0) {
					for (int i = 0; i < q.size(); i++) {
						packet queued_pkt = q.front();
						struct ether_header *eth_hdr_q = (struct ether_header*) queued_pkt.payload;
						struct iphdr *ip_hdr_q = (struct iphdr*)(queued_pkt.payload + FIRST_OFF);

						if (ip_hdr_q->daddr == requested_entry->ip) {
							printf("Pop packet from queue\n");
							eth_hdr_q = (struct ether_header*) queued_pkt.payload;
							memcpy(eth_hdr_q->ether_dhost, requested_entry->mac, 6);

							int send = send_packet(queued_pkt.interface, &m);
							DIE(send == 0, "send_packet");
							q.pop();
						}
					}
				}
			} else {
				printf("neither reply or request (???)\n");
			}
		} else {
			printf("Received malformed packet\n");
		}
	}
}