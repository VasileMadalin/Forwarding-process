//Vasile Madalin Constantin 322CB
#include <queue.h>
#include "skel.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

#define MAX_LINE_LENGTH 300
#define MAX_ADDRESS_LENGTH 20
#define MAX_FILE_DIMENSION 65000
#define ETHER_TYPE_CODE 0x608
#define MAC_VALUE 0xFF

struct route_table_entry {
	int prefix;
	int next_hop;
	int mask;
	int interface;
};

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

//aceasta functie extrage sirurile despartie de spatiu
void parse_line(char *currentline, char *word1, char *word2, 
	char *word3, char *word4) {
	int i, j, p, k;
	for(i = 0; currentline[i] != ' '; i++) {
		word1[i] = currentline[i];
	}
	word1[i] = '\0';

	for(j = i + 1; currentline[j] != ' '; j++) {
		word2[j - i - 1] = currentline[j];
	}
	word2[j - i - 1] = '\0';

	for(k = j + 1; currentline[k] != ' '; k++) {
		word3[k - j - 1] = currentline[k];
	}
	word3[k - j - 1] = '\0';

	for(p = k + 1; currentline[p] != '\0'; p++) {
		word4[p - k - 1] = currentline[p];
	}
	word4[p - k - 1] = '\0';
}

//aceasta functie citeste tabela de routare
int read_rtable(struct route_table_entry *rtable, char * input, 
	int initial_length) {
	FILE *file = fopen(input, "r");

	char currentline[MAX_LINE_LENGTH];

	int length = 0;
	//se citeste linie cu linie din fisierul de intrare
	while (fgets(currentline, sizeof(currentline), file) != NULL) {
		char word1[MAX_ADDRESS_LENGTH], word2[MAX_ADDRESS_LENGTH];
		char word3[MAX_ADDRESS_LENGTH], word4[MAX_ADDRESS_LENGTH];
		//se stocheaza in vectori cele 4 siruri din care este alcatuita o linie
		parse_line(currentline, word1, word2, word3, word4);
		struct in_addr address; 
		inet_aton(word1, &address);
		(rtable + length)->prefix = address.s_addr;
		inet_aton(word2, &address);
		(rtable + length)->next_hop = address.s_addr;
		inet_aton(word3, &address);
		(rtable + length)->mask = address.s_addr;
		(rtable + length)->interface = atoi(word4);
		length = length + 1;
		//se realoca vectorul de structuri
		if (initial_length == length) {
			initial_length = 2 * initial_length;
			rtable = 
			realloc(rtable, initial_length * sizeof(struct route_table_entry));
		}
	}
	fclose(file);
	return length;
}
//aceasta functie gaseste ce mai buna ruta pentru a trimite pachetul
void get_best_route(int *index, __u32 dest_ip, int rtable_size, 
	struct route_table_entry * rtable) {
	int i;
	int j = -1;
	int max = 0;
	for(i = 0; i < rtable_size; i++) {
		if ((rtable[i].mask & dest_ip) == rtable[i].prefix) {
			if (rtable[i].mask > max) {
				max = rtable[i].mask;
				j = i;
			}
		}
	}
	*index = j;
}

//aceasta functie verifica daca exista un arp, 
//care trebuie rezolvat
list get_check(uint32_t ip, list lista) {
	list p;
	for(p = lista; p != NULL; p = p->next) {
		if (((struct arp_entry *)p->element)->ip == ip) 
			break;
	}
	return p;
}

//aceasta functie seteaza o adresa MAC la o anumita valoare
void set_mac_to_a_value(u_char *mac, char c) {
	mac[0] = c;
	mac[1] = c;
	mac[2] = c;
	mac[3] = c;
	mac[4] = c;
	mac[5] = c;
}

int main(int argc, char *argv[]) {
	packet m;
	int rc, rtable_size = 0;

	int initial_length = MAX_FILE_DIMENSION;
	struct route_table_entry *rtable = malloc(initial_length * 
		sizeof(struct route_table_entry));
	
	rtable_size = read_rtable(rtable, argv[1], initial_length);

	init(argc - 2, argv + 2);

	list lista = NULL;

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct arp_header *arp = parse_arp(m.payload);
		struct ether_header *my_eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *my_ip_hdr = 
		(struct iphdr *) (m.payload + sizeof(struct ether_header));
		
		//verificam daca exista un arp
		if (arp != NULL) {
			//verificam tipul arp-ului
			if (ntohs(arp->op) == 1) {//arp request
				//se creeaza o noua structura in care se memoreaza ip si spa
				struct arp_entry *aux_entry = malloc(sizeof(struct arp_entry));
				aux_entry->ip = arp->spa;

				aux_entry->mac[0] = arp->sha[0];
				aux_entry->mac[1] = arp->sha[1];
				aux_entry->mac[2] = arp->sha[2];
				aux_entry->mac[3] = arp->sha[3];
				aux_entry->mac[4] = arp->sha[4];
				aux_entry->mac[5] = arp->sha[5];

				int ok = 1;
				//se verfica daca arp-ul este pus in lisa de asteptare
				for(list p = lista; p != NULL; p = p->next) {
					if (((struct arp_entry *)p->element)->ip == aux_entry->ip 
						&& ((struct arp_entry *)p->element)->mac == 
						aux_entry->mac)
						ok = 0;
				}	
				//daca nu este, se adauga in lista
				if (ok == 1) {
					lista = cons(aux_entry, lista);
				}

				struct ether_header eth_copy;

				eth_copy.ether_dhost[0] = arp->sha[0];
				eth_copy.ether_dhost[1] = arp->sha[1];
				eth_copy.ether_dhost[2] = arp->sha[2];
				eth_copy.ether_dhost[3] = arp->sha[3];
				eth_copy.ether_dhost[4] = arp->sha[4];
				eth_copy.ether_dhost[5] = arp->sha[5];
				

				get_interface_mac(m.interface, eth_copy.ether_shost);
				eth_copy.ether_type = htons(ETHERTYPE_ARP);
				send_arp(arp->spa, arp->tpa, &eth_copy, m.interface, 
					htons(ARPOP_REPLY));
			}
			else {
				//cazul in care avem arp reply
				struct arp_entry *aux_entry = malloc(sizeof(struct arp_entry));
				aux_entry->ip = arp->spa;

				aux_entry->mac[0] = arp->sha[0];
				aux_entry->mac[1] = arp->sha[1];
				aux_entry->mac[2] = arp->sha[2];
				aux_entry->mac[3] = arp->sha[3];
				aux_entry->mac[4] = arp->sha[4];
				aux_entry->mac[5] = arp->sha[5];

				int ok = 1;
				//se adauga in lista de asteptare
				for(list p = lista; p != NULL; p = p->next) {
					if (((struct arp_entry *)p->element)->ip == aux_entry->ip 
						&& ((struct arp_entry *)p->element)->mac 
						== aux_entry->mac) 
						ok = 0;
				}	

				if (ok == 1) {
					lista = cons(aux_entry, lista);
				}
			}
		}
		else {
			//verifica daca pachetul este destinat router-ului
			struct in_addr aux_addr;
			inet_aton(get_interface_ip(m.interface), &aux_addr);
			//pachetul nu este destinat router-ului
			if (my_ip_hdr->daddr != aux_addr.s_addr) {
				if (my_ip_hdr->ttl < 2) {
					//in cazul in care ttl este mai mic decat 2,s e trimite un 
					//icmp de eroare, pentru ca timpul de supravietuire al 
					//mesajului n este suficient pentru trimiterea mesajului
					struct ether_header copy;
					get_interface_mac(m.interface, copy.ether_shost);
					send_icmp_error(my_ip_hdr->saddr, my_ip_hdr->daddr, 
						copy.ether_shost, my_eth_hdr->ether_shost, 11, 0, 
						m.interface);
				}
				else {
					if(ip_checksum(my_ip_hdr, sizeof(struct iphdr)) == 0) {
						int index = -1;
						//se gaseste o ruta pentru trimiterea mesajului
						get_best_route(&index, my_ip_hdr->daddr, rtable_size, rtable);
						if (index != -1) {
							struct route_table_entry *route_to_go_now = rtable + index;
							list p = get_check(route_to_go_now->next_hop, lista);

							if (p != NULL) {

								my_ip_hdr->ttl = my_ip_hdr->ttl - 1;

								my_eth_hdr->ether_dhost[0] = 
								((struct arp_entry *)p->element)->mac[0];
								my_eth_hdr->ether_dhost[1] = 
								((struct arp_entry *)p->element)->mac[1];
								my_eth_hdr->ether_dhost[2] = 
								((struct arp_entry *)p->element)->mac[2];
								my_eth_hdr->ether_dhost[3] = 
								((struct arp_entry *)p->element)->mac[3];
								my_eth_hdr->ether_dhost[4] = 
								((struct arp_entry *)p->element)->mac[4];
								my_eth_hdr->ether_dhost[5] = 
								((struct arp_entry *)p->element)->mac[5];
								

								get_interface_mac(route_to_go_now->interface, 
									my_eth_hdr->ether_shost);
								my_ip_hdr->check = 0;
								my_ip_hdr->check = ip_checksum(my_ip_hdr, 
									sizeof(struct iphdr));
								send_packet(route_to_go_now->interface, &m);
							} 
							else {
								set_mac_to_a_value(my_eth_hdr->ether_dhost, MAC_VALUE);

								my_eth_hdr->ether_type = ETHER_TYPE_CODE;

								get_interface_mac(route_to_go_now->interface, 
									my_eth_hdr->ether_shost);
								struct in_addr aux_address;
								inet_aton(get_interface_ip(route_to_go_now->interface), &aux_address);
								send_arp(route_to_go_now->next_hop, aux_address.s_addr, 
									my_eth_hdr, route_to_go_now->interface,
									htons(ARPOP_REQUEST));
								continue;
							}
						}
						else {
							//daca nu se gaseste ruta, se trimite icmp de eroare
							send_icmp_error(my_ip_hdr->saddr, my_ip_hdr->daddr, 
								my_eth_hdr->ether_dhost, my_eth_hdr->ether_shost, 3, 0, 
								m.interface);
						}
					}
				}
			}
			else {
				//se trimite icmp in cazul in care pachetul este destinat router-ului
				send_icmp(my_ip_hdr->saddr, my_ip_hdr->daddr, my_eth_hdr->ether_dhost, 
				my_eth_hdr->ether_shost, 0, 0, 0, 0, 0);				
			}
		}
	}
}
