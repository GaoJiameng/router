#ifndef FIREWALL_OP_H
#define FIREWALL_OP_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "send.h"

extern void read_firewall_config(IPTABLE *head);     // 读取防火墙配置文档信息入链表
extern void write_firewall_config(IPTABLE *head);       // 写链表信息入防火墙配置文档
extern int msg_deal(char *msg_src , IPTABLE *head , char *str);     //切割记录至一段段（原记录 ，切割后的记录， 切割条件字符）
extern void firewall_cmd(IPTABLE *head);

#endif