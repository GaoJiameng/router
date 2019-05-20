#ifndef SEND_H
#define SEND_H
  
#include<netpacket/packet.h>//struct sockaddr_ll  
#include<sys/ioctl.h>//ioctl  
#include<net/if.h>//struct ifreq  
#include<net/ethernet.h>//struct ether_header  
#include<net/if_arp.h>//struct arphdr  
#include "recv.h"

extern void show_information(void);  //显示帮助信息
extern int send_arp(char src_ip[] , char dst_ip[] , unsigned char src_mac[] , char card_name[] , int op);   //发送arp数据包 op=1 为arp请求 op=2 为arp应答
extern void firewall_cmd(IPTABLE *head);
extern void dectohex(char ip[] , unsigned char fin_ip[]);               //  点分十进制ip 转 十六进制ip

#endif