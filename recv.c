#include "./head/recv.h"

int recv_socket(ARPTABLE *head , IPTABLE *ip_firewall_head)     //接收网络信息
{
     //创建原始套接字  
    int sockfd = socket(PF_PACKET  ,SOCK_RAW , htons(ETH_P_ALL));
    if(sockfd < 0)
    {
        perror("socket");
        return 0;
    }

    IPTABLE *sign_fire_in;
    sign_fire_in = (IPTABLE *)malloc(sizeof(IPTABLE));

    IPTABLE *sign_fire_out;
    sign_fire_out = (IPTABLE *)malloc(sizeof(IPTABLE));

    //接收链路层数据
    while(1)
    {
        unsigned char buf[1600]="";
        //buf将来存放的是完整的帧数据 mac头 IP头   tcp/udp头  应用数据 
        int ret = recvfrom(sockfd , buf , sizeof(buf) , 0 , NULL ,NULL);
        if(ret < 0)
        {
            perror("recvfrom");
            break;
        }

        unsigned char src_mac[6]="";
        unsigned char dst_mac[6]="";
        memcpy(dst_mac , buf , 6);
        memcpy(src_mac , buf+6 , 6);

        //mac协议分析
        unsigned short macType = ntohs(*(unsigned short *)(buf + 12));


        if(macType == 0x0800)       //IP数据包
        {
            // 让ip_buf指向ip报文头部起始位置
            unsigned char *ip_buf = buf+14;

            unsigned char src_ip[4]=""; 
            unsigned char dst_ip[4]="";
            memcpy(src_ip , ip_buf+12 , 4);
            memcpy(dst_ip , ip_buf+16 , 4);

            sign_fire_in = search_ip_firewall(ip_firewall_head , src_ip , 1);   //防火墙判断进入
            sign_fire_out = search_ip_firewall(ip_firewall_head , dst_ip , 1);
            if(sign_fire_in != NULL || sign_fire_out != NULL)
            {
                continue;
            }

            int i = 0; 
            int card_num = 0; 
            ARPTABLE *arp_temp;    
            arp_temp = (ARPTABLE *)malloc(sizeof(ARPTABLE));

            char ip_src_addr [16] = "";
            char ip_dst_addr [16] = "";
            hextodec(dst_ip , ip_dst_addr);    //点分十进制 dst_ip


            //判断目的ip 和 哪个网卡是一个网段
            for(i = 0 ; i < get_interface_num() ; i++)
            {
                if(memcmp(net_interface[i].ip , dst_ip , 3) == 0)
                    {
                        card_num = i;
                    }
            }
            //判断arp缓存表中是否有对应记录    
            arp_temp = search_ip_link_list(head , dst_ip);

            if(arp_temp == NULL)
            {
                //arp 记录不存在 发送arp包
                hextodec(net_interface[card_num].ip , ip_src_addr);    //点分十进制 虚拟机网卡ip
                send_arp(ip_src_addr , ip_dst_addr , net_interface[card_num].mac , net_interface[card_num].name , 1);   // op=1 为arp请求 
            }
            else if(arp_temp != NULL)
            {

                memcpy(buf,arp_temp->arp_table_mac,6);//修改目的mac       

                //转发ICMP包
                struct ifreq ifq;
                strncpy(ifq.ifr_name , net_interface[card_num].name , IFNAMSIZ);
                ioctl(sockfd,SIOCGIFINDEX,&ifq);
                struct sockaddr_ll sll;
                bzero(&sll,sizeof(sll));//清空结构体变量 sll
                sll.sll_ifindex = ifq.ifr_ifindex;

                sign_fire_out = search_ip_firewall(ip_firewall_head , dst_ip , 0);   //防火墙判断出
                sign_fire_in = search_ip_firewall(ip_firewall_head , src_ip , 0);
                if(sign_fire_in != NULL || sign_fire_out != NULL)
                {
                    continue;
                }

                sendto(sockfd,buf,ret,0,(struct sockaddr *)&sll,sizeof(sll));
            }
        }  
        else if(macType == 0x0806)  //ARP数据包
        {  
            unsigned char src_mac[6]="";
            memcpy(src_mac, buf + 22 , 6 );

            //让ip_buf指向ip报文头部起始位置
            unsigned char *ip_buf = buf+28;
            unsigned char src_ip[4]="";  
            memcpy(src_ip, ip_buf , 4);

            sign_fire_in = search_ip_firewall(ip_firewall_head , src_ip , 1);   //防火墙判断进入
            if(sign_fire_in != NULL)
            {
                continue;
            }
            insert_linklist(head , src_ip , src_mac);
        }  
        else if(macType == 0x8035)  //RARP数据包
        {  
            //printf("rarp数据包\n");
            break;  
        }  
    }  

    close(sockfd);  
    return 0;  

}


ARPTABLE *insert_linklist(ARPTABLE *head , unsigned char ip[] , unsigned char mac[])        //存链表 并且判断链表有无相关项
{
    ARPTABLE *temp;
    temp = (ARPTABLE *)malloc(sizeof(ARPTABLE));
    temp = search_ip_link_list(head , ip);
    if(temp == NULL)
    {   
        ARPTABLE *new;
        new = (ARPTABLE *)malloc(sizeof(ARPTABLE));
        memcpy(new->arp_table_ip , ip , 4);
        memcpy(new->arp_table_mac , mac , 6);   
        add_link_list(head , new);
    }
    return NULL;
}



void hextodec(unsigned char ip[] , char fin_ip[])               //十六进制ip 转 点分十进制ip
{

    inet_ntop(AF_INET, (unsigned int *)ip, fin_ip, INET_ADDRSTRLEN);

    return;
}


void network_card_status(void)
{
    int i = 0;
    puts("");
    puts("**************  NETWORK CARD STATUS  ***************");
    puts("------------start------------------start------------");
    for(i = 0 ; i < get_interface_num() ; i++)
    { 
        puts("");
        printf("-_-_-_-  network card number : %d  _-_-_-_\n" , i);
        printf("netcard name : %s\n" ,net_interface[i].name);		//接口名字
        printf("netcard ip : %d.%d.%d.%d\n" ,net_interface[i].ip[0] , 
                                                net_interface[i].ip[1] , 
                                                net_interface[i].ip[2] , 
                                                net_interface[i].ip[3]);	//IP地址
        printf("netcard mac : %02x:%02x:%02x:%02x:%02x:%02x\n" ,net_interface[i].mac[0] , 
                                                            net_interface[i].mac[1] , 
                                                            net_interface[i].mac[2] , 
                                                            net_interface[i].mac[3] ,
                                                            net_interface[i].mac[4] ,
                                                            net_interface[i].mac[5] );   //MAC地址
        printf("netcard netmask : %d.%d.%d.%d\n" ,net_interface[i].netmask[0] , 
                                                net_interface[i].netmask[1] , 
                                                net_interface[i].netmask[2] , 
                                                net_interface[i].netmask[3]);     //子网掩码       
        printf("netcard broadcast : %d.%d.%d.%d\n" ,net_interface[i].br_ip[0] , 
                                                net_interface[i].br_ip[1] , 
                                                net_interface[i].br_ip[2] , 
                                                net_interface[i].br_ip[3]);       //广播地址    
        if(net_interface[i].flag == 1)       //状态
        {
            printf("netcard status : online \n");
        }                       
        else if(net_interface[i].flag == 0)
        {
            printf("netcard status : offline \n");
        }	
        puts("-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_");        
        puts("");	
    }
    puts("-------------end--------------------end-------------");
    puts("");
}