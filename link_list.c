#include "./head/link_list.h"


ARPTABLE *init_link_list(ARPTABLE *pnew)   //节点初始化
{
    memcpy(pnew->arp_table_ip , "" , 4);
    memcpy(pnew->arp_table_mac , "" , 6);
    pnew->next = NULL;
    return pnew;
}

IPTABLE *init_ip_firewall(IPTABLE *pnew)   //ip_firewall节点初始化
{
    pnew->action = 0;
    memcpy(pnew->ip_firewall , "" , 4);
    pnew->next = NULL;
    return pnew;
}

ARPTABLE *add_link_list(ARPTABLE *head , ARPTABLE *pnew)   //添加节点
{
    pnew->next = head->next;
	head->next = pnew;
	return head;
}

IPTABLE *add_ip_firewall(IPTABLE *head , IPTABLE *pnew)   //添加ip_firewall节点
{
    pnew->next = head->next;
	head->next = pnew;
	return head;
}

int del_ip_firewall(IPTABLE *head , unsigned char ip[] , int action)   //删除firewall 对应的ip节点
{
    IPTABLE *pnew;
    IPTABLE *del;
	pnew = (IPTABLE *)malloc(sizeof(IPTABLE));
    del = (IPTABLE *)malloc(sizeof(IPTABLE));
	pnew = head;
	while(pnew->next != NULL)
	{
		if((memcmp(ip , pnew->next->ip_firewall , 4) == 0) && (pnew->next->action == action))
		{
			if(pnew->next->next != NULL)
            {
                del = pnew->next;
                pnew->next = pnew->next->next;
                free(del);
            }
            else if(pnew->next->next == NULL)
            {
                del = pnew->next;
                pnew->next = NULL;
                free(del);
            }
            return 1;
		}
		pnew = pnew->next;
	}
	return 0;
}

ARPTABLE *search_ip_link_list(ARPTABLE *head , unsigned char ip[])    //按照ip查找 arp表
{
	ARPTABLE *pnew;
	pnew = (ARPTABLE *)malloc(sizeof(ARPTABLE));
	pnew = head;
	while(pnew->next != NULL)
	{
		if(memcmp(ip , pnew->next->arp_table_ip , 4) == 0)
		{
			return pnew->next;
		}
		pnew = pnew->next;
	}
	return NULL;
}

IPTABLE *search_ip_firewall(IPTABLE *head , unsigned char ip[] , int action)    //按照ip查找 ip_firewall表
{
	IPTABLE *pnew;
	pnew = (IPTABLE *)malloc(sizeof(IPTABLE));
	pnew = head;
	while(pnew->next != NULL)
	{
		if((memcmp(ip , pnew->next->ip_firewall , 4) == 0) && (pnew->next->action == action))
		{
			return pnew->next;
		}
		pnew = pnew->next;
	}
	return NULL;
}

ARPTABLE *arp_traverse_linklist(ARPTABLE *head)     //遍历所有arp节点
{	
	ARPTABLE *pnew;
	pnew = (ARPTABLE *)malloc(sizeof(ARPTABLE));
	pnew = head;
    puts("");
    puts("**********************************  ARP LINK LIST  ************************************");
    puts("------------------start------------------start----------------------start--------------");
	while(pnew->next != NULL)
	{	
		printf("arp ip = %d.%d.%d.%d",pnew->next->arp_table_ip[0],
                pnew->next->arp_table_ip[1],pnew->next->arp_table_ip[2],
                pnew->next->arp_table_ip[3]);
        printf("  ------->  ");
		printf("arp mac = %x:%x:%x:%x:%x:%x\n",
                pnew->next->arp_table_mac[0],pnew->next->arp_table_mac[1],
                pnew->next->arp_table_mac[2],pnew->next->arp_table_mac[3],
                pnew->next->arp_table_mac[4],pnew->next->arp_table_mac[5]); 
		pnew = pnew->next;
	}
    puts("-------------------end--------------------end------------------------end---------------");
    puts("");
	return head;
}

IPTABLE *traverse_ip_firewall(IPTABLE *head)     //遍历所有ip_firewall节点
{	
	IPTABLE *pnew;
	pnew = (IPTABLE *)malloc(sizeof(IPTABLE));
	pnew = head;
    puts("");
    puts("*******************  IP FIREWALL LIST  *******************");
    puts("--------------start--------------------start--------------");
	while(pnew->next != NULL)
	{	
        if(pnew->next->action == 1)
        {
            printf("Block access");      //阻止进入路由器
        }
        else if(pnew->next->action == 0)
        {
            printf("Block out");         //阻止出路由器
        }
        printf("  ---->  ");
		printf("ip firewall = %d.%d.%d.%d\n",pnew->next->ip_firewall[0],
                pnew->next->ip_firewall[1],pnew->next->ip_firewall[2],
                pnew->next->ip_firewall[3]);
		pnew = pnew->next;
	}
    puts("--------------end----------------------end---------------");
    puts("");
	return head;
}