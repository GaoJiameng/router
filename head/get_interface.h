#ifndef GET_INTERFACE_H
#define GET_INTERFACE_H

#define MAXINTERFACES 16    /* 最大接口数 */

typedef struct interface{
	char name[20];		//接口名字
	unsigned char ip[4];		//IP地址
	unsigned char mac[6];		//MAC地址
	unsigned char netmask[4];	//子网掩码
	unsigned char br_ip[4];		//广播地址
	int  flag;			//状态
}INTERFACE;
extern INTERFACE net_interface[MAXINTERFACES];//接口数据

/******************************************************************
函	数:	int getinterface()
功	能:	获取接口信息
参	数:	无
*******************************************************************/
extern void getinterface();

/******************************************************************
函	数:	int get_interface_num()
功	能:	获取实际接口数量
参	数:	接口数量
*******************************************************************/
int get_interface_num();


#endif
