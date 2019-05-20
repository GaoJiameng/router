#include <sys/types.h>   //open
#include <sys/stat.h>    //open
#include <fcntl.h>       //open
#include <unistd.h>      //_exit
#include <pthread.h>     //pthread
#include <string.h>
#include <stdlib.h>

#include "./head/send.h"

void *get_net_data(void *arg);
void *cmd_from_keyboard(void *arg);

//新建链表头结点 （全局链表）
ARPTABLE *head;
IPTABLE *ip_firewall_head;



int main(int argc, char const *argv[])
{
    puts("Please input help for more information!");
    //获取接口信息
    getinterface();
    //初始化头结点
    head = (ARPTABLE *)malloc(sizeof(ARPTABLE));  
    init_link_list(head);
    ip_firewall_head = (IPTABLE *)malloc(sizeof(IPTABLE));
    init_ip_firewall(ip_firewall_head);

    // read_firewall_config(ip_firewall_head);    // 读取防火墙配置文档信息入链表

    //创建线程tid 
    pthread_t tid1 = 0;  
    pthread_t tid2 = 0;
    //创建线程  
    pthread_create(&tid1, NULL,get_net_data, NULL);               //1号线程   读取网络数据
    pthread_create(&tid2, NULL,cmd_from_keyboard, NULL);          //2号线程   读取键盘输入
    //等待线程结束  
    void *ret=NULL;  
    pthread_join(tid1, &ret);       
    pthread_join(tid2, &ret); 

    return 0;
}

void *get_net_data(void *arg)
{
    while(1)
    {
        recv_socket(head , ip_firewall_head);  //接收网络消息
    }
    
    return NULL;
}

void *cmd_from_keyboard(void *arg)
{
    while(1)
    {
        char cmd[20] = "";
        fgets(cmd , sizeof(cmd) , stdin); 
        cmd[strlen(cmd)-1]=0;//去掉键盘输入的回车符  
        if(strcmp(cmd , "help") == 0 )
        {
            show_information();//显示help信息
        }
        else if(strcmp(cmd , "arp") == 0 )  //查看路由器的arp表
        {
            arp_traverse_linklist(head);             
        }
        else if(strcmp(cmd , "ifconfig") == 0 )   //查看路由器网卡信息
        {
            network_card_status();
        }
        else if(strcmp(cmd , "firewall") == 0 )  //设置防火墙
        {
            firewall_cmd(ip_firewall_head);
        }
        else if(strcmp(cmd , "lsfire") == 0 )   //查看防火墙
        {
            traverse_ip_firewall(ip_firewall_head); //遍历防火墙
        }
    }
    
    return NULL;
}
