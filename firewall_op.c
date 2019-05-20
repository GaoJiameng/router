#include "./head/firewall_op.h"


void read_firewall_config(IPTABLE *head)       // 读取防火墙配置文档信息入链表
{  
    //创建防火墙配置文件 套接字
    int read_fw_fd;
    unsigned char fw_buf[200] = "";  //fw记录临时存储数组
    read_fw_fd = open("./config/firewall.config", O_RDONLY | O_CREAT);  //只读 无就创建
    if(read_fw_fd < 0)
    {
        perror("open");
        _exit(-1);
    }
    memset(fw_buf, 0 , 200);
    if((read(read_fw_fd , fw_buf ,sizeof(fw_buf))) == -1)
        {
            perror("read");
            exit(1);        
        }
    close(read_fw_fd);
    //字符串切割  存入链表(function)
    msg_deal(fw_buf , head , "\n");

}

void write_firewall_config(IPTABLE *head)       // 写链表信息入防火墙配置文档
{
    //创建防火墙配置文件 套接字
    int write_fw_fd;
    write_fw_fd = open("./config/firewall.config", O_WRONLY | O_TRUNC);   //只写  覆盖源文件
    if(write_fw_fd < 0)
    {
        perror("open");
        _exit(-1);
    }

    // 写链表信息入防火墙配置文档
    if((write(write_fw_fd , cmd , strlen(cmd))) == -1 )
    {
        perror("write");
        exit(1); 
    }

    close(write_fw_fd);
}

int msg_deal(char msg_src[] , IPTABLE *head , char *str)     //切割记录至一段段（原记录 ，切割后的记录， 切割条件字符）
{
	int i = 0;
    int t = 0;
    char *msg_done[50];
	msg_done[i]=strtok(msg_src,str);					   //切割套路
	while(msg_done[i])
	{
		i++;
		msg_done[i]=strtok(NULL,str);
	}

    for(t = 0 ; t < i ; t++)
    {
        int action = 5;
        char src_ip[16]="";
        unsigned char ip[4]="";
        IPTABLE *temp;
        temp = (IPTABLE *)malloc(sizeof(IPTABLE));
        action = atoi(strtok( msg_done[t],"-"));				    //切割套路
        src_ip = strtok(NULL,"-");
        memcpy(ip , inet_addr(src_ip) , 4);
        temp = search_ip_firewall(IPTABLE *head , ip , action);
        if(temp == NULL)   //添加记录
        {
            temp->action = action;
            memcpy(temp->ip_firewall , ip , 4);
            add_ip_firewall(head , temp);
        }
        
    }
    return 0;
} 

void firewall_cmd(IPTABLE *head)
{
    //判断是 添加 还是 删除 记录
    puts("what would want to add a record or delete to firewall? (add or del):");
    char cmd_op[20] = "";
    fgets(cmd_op , sizeof(cmd_op) , stdin); 
    cmd[strlen(cmd_op)-1]=0;//去掉键盘输入的回车符 
    if(strncmp(cmd_op , "add" , 3) == 0)    //添加记录
    {
        puts("Please input setting type : add a block access record or block out record(access or out):");
        char cmd_add[20] = "";
        fgets(cmd_add , sizeof(cmd_add) , stdin); 
        cmd[strlen(cmd_add)-1]=0;//去掉键盘输入的回车符  
        if(strncmp(cmd_add , "access" , 6) == 0)    //阻止进入路由器
        {
            puts("Please input ip:");
            char cmd_ip[20] = "";
            fgets(cmd_ip , sizeof(cmd_ip) , stdin); 
            cmd[strlen(cmd_ip)-1]=0;//去掉键盘输入的回车符 

            //判断记录链表中有无（函数）
            //存记录至链表（函数）
            //存链表至文件（函数）追加源文件
        }
        else if(strncmp(cmd_add , "out" , 3) == 0)   //阻止出路由器
        {
            puts("Please input ip:");
            char cmd_ip[20] = "";
            fgets(cmd_ip , sizeof(cmd_ip) , stdin); 
            cmd[strlen(cmd_ip)-1]=0;//去掉键盘输入的回车符 

            //判断记录链表中有无（函数）
            //存记录至链表（函数）
            //存链表至文件（函数）追加源文件
        }
    }
    else if(strncmp(cmd_op , "del" , 3) == 0)     //删除记录
    {
        puts("Please input setting type : del a block access record or block out record(access or out):");
        char cmd_add[20] = "";
        fgets(cmd_add , sizeof(cmd_add) , stdin); 
        cmd[strlen(cmd_add)-1]=0;//去掉键盘输入的回车符  
        if(strncmp(cmd_add , "access" , 6) == 0)    //阻止进入路由器
        {
            puts("Please input ip:");
            char cmd_ip[20] = "";
            fgets(cmd_ip , sizeof(cmd_ip) , stdin); 
            cmd[strlen(cmd_ip)-1]=0;//去掉键盘输入的回车符 
            
            //判断记录链表中有无（函数）
            //删链表记录（函数）
            //存链表至文件（函数）追加源文件
        }
        else if(strncmp(cmd_add , "out" , 3) == 0)   //阻止出路由器
        {
            puts("Please input ip:");
            char cmd_ip[20] = "";
            fgets(cmd_ip , sizeof(cmd_ip) , stdin); 
            cmd[strlen(cmd_ip)-1]=0;//去掉键盘输入的回车符 

            //判断记录链表中有无（函数）
            //删链表记录（函数）
            //存链表至文件（函数）追加源文件
        }
    }  
}