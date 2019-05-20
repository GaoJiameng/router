#include "./head/send.h"
#include "./head/recv.h"


void show_information(void)
{
    puts("****************************************************************");
    puts("*** help:       print information of help                    ***");
    puts("*** arp:        check the arp table of router                ***");
    puts("*** ifconfig:   check the network card information of router ***");
    puts("*** firewall:   set firewall                                 ***");
    puts("*** lsfire:     check firewall                               ***");
    puts("****************************************************************");
}

int send_arp(char src_ip[] , char dst_ip[] , unsigned char src_mac[] , char card_name[] , int op)  
{  
    //创建原始套接字  
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
    if(sockfd < -1)
    {
        perror("socket");
        return 0;
    } 

    // unsigned char src_mac[6] = {0x00,0x1c,0x42,0x4e,0x1d,0xac};//虚拟机的mac  
    unsigned char msg[1600]="";  
    //组mac头  
    struct ether_header *ethHdr = (struct ether_header *)msg;  
    memset(ethHdr->ether_dhost,0xff, 6);//目的mac  
    memcpy(ethHdr->ether_shost,src_mac,6);//源mac  
    ethHdr->ether_type = htons(0x0806);//mac的协议类型  
   
     //组arp头  
    struct arphdr *arp_hdr = (struct arphdr *)(msg+14);//跳过mac头  
    arp_hdr->ar_hrd = htons(1);//硬件类型  
    arp_hdr->ar_pro = htons(0x0800);//软件协议类型  
    arp_hdr->ar_hln = 6;//硬件地址长度  
    arp_hdr->ar_pln = 4;//软件地址长度  
    arp_hdr->ar_op = htons(op);//arp 请求 为1  
    memcpy(arp_hdr->__ar_sha, src_mac, 6);//源mac  
    *(unsigned int *)(arp_hdr->__ar_sip) = inet_addr(src_ip);//虚拟机IP 源IP  
    memset(arp_hdr->__ar_tha, 0, 6);//arp的请求报文 目的mac为0  
    *(unsigned int *)(arp_hdr->__ar_tip) = inet_addr(dst_ip);//目的IP  
       
      
    //将arp请求报文 通过”ens33或eth0“发送出去  
    //使用ioctl 通过接口名称ens33或eth0得到本地接口地址  
    struct ifreq  ifq;  
    strncpy(ifq.ifr_name, card_name, IFNAMSIZ);  
    if(ioctl(sockfd, SIOCGIFINDEX, &ifq) == -1)  
    {  
         perror("ioctl");  
         return 0;  
    }  
    // sendto(sockfd, msg, 实际长度,0, 出去的本地接口, 接口长度);  
    //本机接口地址  
    struct sockaddr_ll sll;  
    bzero(&sll, sizeof(sll));  
    sll.sll_ifindex = ifq.ifr_ifindex;  
    sendto(sockfd, msg, 42,0, (struct sockaddr *)&sll, sizeof(sll));  
     
    close(sockfd);  
    return 0;  
}  


void firewall_cmd(IPTABLE *head)
{
    int sign = 0;
    IPTABLE *temp;
    temp = (IPTABLE *)malloc(sizeof(IPTABLE));
    IPTABLE *pnew;
    pnew = (IPTABLE *)malloc(sizeof(IPTABLE));
    unsigned char ip[4] = "";
    //判断是 添加 还是 删除 记录
    puts("what would want to add a record or delete to firewall? (add or del):");
    char cmd_op[20] = "";
    fgets(cmd_op , sizeof(cmd_op) , stdin); 
    cmd_op[strlen(cmd_op)-1]=0;//去掉键盘输入的回车符 
    if(strncmp(cmd_op , "add" , 3) == 0)    //添加记录
    {
        puts("Please input setting type : add a block access record or block out record(access or out):");
        char cmd_add[20] = "";
        fgets(cmd_add , sizeof(cmd_add) , stdin); 
        cmd_add[strlen(cmd_add)-1]=0;//去掉键盘输入的回车符  
        if(strncmp(cmd_add , "access" , 6) == 0)    //阻止进入路由器
        {
            puts("Please input ip:");
            char cmd_ip[20] = "";
            fgets(cmd_ip , sizeof(cmd_ip) , stdin); 
            cmd_ip[strlen(cmd_ip)-1]=0;//去掉键盘输入的回车符 

            dectohex(cmd_ip , ip);
            //判断记录链表中有无
            temp = search_ip_firewall(head , ip , 1);  
            if(temp == NULL)   //存记录至链表
            {
                pnew->action = 1;
                memcpy(pnew->ip_firewall , ip , 4);
                add_ip_firewall(head , pnew); 
            }
            else
            {
                puts("record already exist!");
            }
            
            
            //存链表至文件 追加源文件
        }
        else if(strncmp(cmd_add , "out" , 3) == 0)   //阻止出路由器
        {
            puts("Please input ip:");
            char cmd_ip[20] = "";
            fgets(cmd_ip , sizeof(cmd_ip) , stdin); 
            cmd_ip[strlen(cmd_ip)-1]=0;//去掉键盘输入的回车符 

            dectohex(cmd_ip , ip);
            //判断记录链表中有无
            temp = search_ip_firewall(head , ip , 0);
            if(temp == NULL)   //存记录至链表
            {
                pnew->action = 0;
                memcpy(pnew->ip_firewall , ip , 4);
                add_ip_firewall(head , pnew); 
            }
            else
            {
                puts("record already exist!");
            }

            //存链表至文件追加源文件
        }
    }
    else if(strncmp(cmd_op , "del" , 3) == 0)     //删除记录
    {
        puts("Please input setting type : del a block access record or block out record(access or out):");
        char cmd_add[20] = "";
        fgets(cmd_add , sizeof(cmd_add) , stdin); 
        cmd_add[strlen(cmd_add)-1]=0;//去掉键盘输入的回车符  
        if(strncmp(cmd_add , "access" , 6) == 0)    //阻止进入路由器
        {
            puts("Please input ip:");
            char cmd_ip[20] = "";
            fgets(cmd_ip , sizeof(cmd_ip) , stdin); 
            cmd_ip[strlen(cmd_ip)-1]=0;//去掉键盘输入的回车符 
            
            dectohex(cmd_ip , ip);
            //判断记录链表中有无 删链表记录
            sign = del_ip_firewall(head , ip , 1);
            if(sign == 1)
            {
                puts("delete success!");
            }        
            else
            {
                puts("delete failed!");
            }      
            //存链表至文件追加源文件
        }
        else if(strncmp(cmd_add , "out" , 3) == 0)   //阻止出路由器
        {
            puts("Please input ip:");
            char cmd_ip[20] = "";
            fgets(cmd_ip , sizeof(cmd_ip) , stdin); 
            cmd_ip[strlen(cmd_ip)-1]=0;//去掉键盘输入的回车符 

            dectohex(cmd_ip , ip);
           //判断记录链表中有无 删链表记录
            sign = del_ip_firewall(head , ip , 0);
            if(sign == 1)
            {
                puts("delete success!");
            }        
            else
            {
                puts("delete failed!");
            }
            
            //存链表至文件追加源文件
        }
    }  
}




void dectohex(char ip[] , unsigned char fin_ip[])               //  点分十进制ip 转 十六进制ip
{

    inet_pton(AF_INET, ip, (unsigned int *)fin_ip);
    return;
}