#ifndef LINK_LIST_H
#define LINK_LIST_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "get_interface.h"


typedef struct arp_list{
    unsigned char arp_table_ip[4];
    unsigned char arp_table_mac[6];
    struct arp_list *next;
}ARPTABLE;

typedef struct ip_table{
    int action;
    unsigned char ip_firewall[4];
    struct ip_table *next;
}IPTABLE;

extern ARPTABLE *init_link_list(ARPTABLE *pnew);                             //节点初始化
extern ARPTABLE *add_link_list(ARPTABLE *head , ARPTABLE *pnew);             //添加节点
extern ARPTABLE *search_ip_link_list(ARPTABLE *head , unsigned char ip[]);   //按照ip查找 arp表
extern ARPTABLE *arp_traverse_linklist(ARPTABLE *head);                      //遍历所有arp节点


extern IPTABLE *init_ip_firewall(IPTABLE *pnew);                                          //ip_firewall节点初始化
extern IPTABLE *add_ip_firewall(IPTABLE *head , IPTABLE *pnew);                           //添加ip_firewall节点
extern IPTABLE *search_ip_firewall(IPTABLE *head , unsigned char ip[] , int action);      //按照ip查找 ip_firewall表
extern IPTABLE *traverse_ip_firewall(IPTABLE *head);                                      //遍历所有ip_firewall节点
extern int del_ip_firewall(IPTABLE *head , unsigned char ip[] , int action);                 //删除firewall 对应的ip节点

#endif
