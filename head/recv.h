#ifndef RECV_H
#define RECV_H


#include<sys/socket.h>//socket  
#include <netinet/ether.h>  
#include<arpa/inet.h>  
#include <unistd.h> 
#include<netpacket/packet.h>//struct sockaddr_ll  
#include<sys/ioctl.h>//ioctl  
#include<net/if.h>//struct ifreq  
#include<net/ethernet.h>//struct ether_header mac结构体头  
#include<net/if_arp.h>//struct arphdr arp结构体头  
#include<netinet/ip.h>//struct iphdr ip结构体头  
#include<netinet/udp.h>//struct udphdr udp结构体头  
#include "link_list.h"
#include "send.h"


extern int recv_socket(ARPTABLE *head  , IPTABLE *ip_firewall_head);         //接收网络信息
extern ARPTABLE *insert_linklist(ARPTABLE *head , unsigned char ip[] , unsigned char mac[]);   //存链表 并且判断链表有无相关项 
extern void hextodec(unsigned char ip[] , char fin_ip[]);               //十六进制ip 转 点分十进制ip
extern void network_card_status(void);       //打印网卡信息

#endif