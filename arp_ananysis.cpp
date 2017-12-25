/**
 * @file arp_analysis.cpp
 */

#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <netinet/in.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>
#include <ctime>
#include <string.h>
#include <sstream> 
 /* 以太网帧首部长度 */
#define ETHER_HEADER_LEN sizeof(struct ether_header)
/* 整个arp结构长度 */
#define ETHER_ARP_LEN sizeof(struct ether_arp)
/* 以太网 + 整个arp结构长度 */
#define ETHER_ARP_PACKET_LEN ETHER_HEADER_LEN + ETHER_ARP_LEN
/* IP地址长度 */
#define IP_ADDR_LEN 4

using namespace std;
/* 第一个参数:是从函数pcap_loop()最后一个参数传递过来的;
 * 第二个参数:表示捕获到的数据包基本信息,包括时间,长度等信息;
 * 第三个参数:表示的捕获到的数据包的内容
 */

int arp_ananysis(struct ether_arp *arp_packet);
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{
    struct ether_header *ethernet_hdrptr; //以太网头部
    unsigned short ethernet_type;         //二层头部的以太网类型  
    struct ether_arp *arp_packet;
    int sock_raw_fd, ret_len, i;
    ethernet_hdrptr = (struct ether_header *)packet;   //以太网头部
    ethernet_type = ntohs(ethernet_hdrptr->ether_type);//获得以太网的类型
    
    if (ethernet_type == ETHERTYPE_ARP) 
    {
	/* 剥去以太头部,得到arp报文部分 */
        arp_packet = (struct ether_arp *)(packet + ETHER_HEADER_LEN);
        /* arp操作码为2代表arp应答 */
	if (ntohs(arp_packet->arp_op) == 1)
	{
            cout<<"==========================arp request packet======================"<<endl;
	    printf("Time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
	    arp_ananysis(arp_packet);
	    cout<<endl;
	}
        else
	{
            cout<<"==========================arp reply packet======================"<<endl;
	    printf("Time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
	    arp_ananysis(arp_packet);
	    cout<<endl;
	}
    }
}  

int arp_ananysis(struct ether_arp *arp_packet){
    int i;
    int sender_ip[4];
    int target_ip[4];
    stringstream sender_ip_ss;
    char sender_mac[17];
    stringstream target_ip_ss;
    char target_mac[17];
    
    /*发送方的IP地址*/
    printf("sender ip:");
    /*ip地址的四段的数据存储在u_int8_t arp_spa[4]数组中*/
    for ( i = 0; i < IP_ADDR_LEN; i++)
        sender_ip[i] = (unsigned int)(arp_packet->arp_spa[i]);
    sender_ip_ss<<sender_ip[0]<<"."<<sender_ip[1]<<"."<<sender_ip[2]<<"."<<sender_ip[3];
    cout<<sender_ip_ss.str()<<endl;
    
       
    /*发送方的MAC地址*/
    printf("sender mac:");
    /*MAC地址的四段的数据存储在u_int8_t arp_sha[ETH_ALEN]数组中,
     *其中ETH_ALEN为6,即以太网地址长度
     */
    sprintf(sender_mac,"%02x",arp_packet->arp_sha[0]);
    sprintf((sender_mac+3),"%02x",arp_packet->arp_sha[1]);
    sprintf((sender_mac+6),"%02x",arp_packet->arp_sha[2]);
    sprintf((sender_mac+9),"%02x",arp_packet->arp_sha[3]);
    sprintf((sender_mac+12),"%02x",arp_packet->arp_sha[4]);
    sprintf((sender_mac+15),"%02x",arp_packet->arp_sha[5]);
    sender_mac[2]=':';
    sender_mac[5]=':';
    sender_mac[8]=':';
    sender_mac[11]=':';
    sender_mac[14]=':';
    /*MAC字符串中小写字母转换成大写字母*/
    int m;
    for (m=0;m<=16;m++){
        if (sender_mac[m]>=97 && sender_mac[m]<=122)
            sender_mac[m] = sender_mac[m] - 32;
    }
    

    cout<<sender_mac<<"\n";
    
    /*接收方的IP地址*/
    printf("target ip:");
    /*ip地址的四段的数据存储在u_int8_t arp_spa[4]数组中*/
    for (i = 0; i < IP_ADDR_LEN; i++)
        target_ip[i] = (unsigned int)(arp_packet->arp_tpa[i]);
    target_ip_ss<<target_ip[0]<<"."<<target_ip[1]<<"."<<target_ip[2]<<"."<<target_ip[3];
    cout<<target_ip_ss.str()<<endl;


    /*接收方的MAC地址*/
    printf("target mac:");
    /*MAC地址的四段的数据存储在u_int8_t arp_tha[ETH_ALEN]数组中,
     *其中ETH_ALEN为6,即以太网地址长度
     */
    sprintf(target_mac,"%02x",arp_packet->arp_tha[0]);
    sprintf((target_mac+3),"%02x",arp_packet->arp_tha[1]);
    sprintf((target_mac+6),"%02x",arp_packet->arp_tha[2]);
    sprintf((target_mac+9),"%02x",arp_packet->arp_tha[3]);
    sprintf((target_mac+12),"%02x",arp_packet->arp_tha[4]);
    sprintf((target_mac+15),"%02x",arp_packet->arp_tha[5]);
    target_mac[2]=':';
    target_mac[5]=':';
    target_mac[8]=':';
    target_mac[11]=':';
    target_mac[14]=':';
    /*MAC字符串中小写字母转换成大写字母*/
    int n=0;
    for (n=0;n<=16;n++){
	if (target_mac[n]>=97 && target_mac[n]<=122)
	    target_mac[n] = target_mac[n] - 32;
    }
    cout<<target_mac<<"\n";



} 
 
int main()  {  
    char errBuf[PCAP_ERRBUF_SIZE], * interfaceName;  
    /*pcap_lookupdev(errBuf):函数用于查找网络设备，返回可被 pcap_open_live() 函数调用的网络设备名指针*/ 
    interfaceName = pcap_lookupdev(errBuf);
      
    if(interfaceName)  
    { 
	cout<<"Listen on interface: "<<interfaceName<<endl<<endl;
    }  
    else  
    {  
      printf("error: %s\n", errBuf);  
      exit(1);  
    }  
    
    /*pcap_open_live(网卡名称,表示捕获的最大字节数,是否开启混杂模式,用于存储错误信息):打开网络设备*/      
    pcap_t * device = pcap_open_live(interfaceName, 65535, 1, 0, errBuf);  
      
    if(!device)  
    {  
      printf("error: pcap_open_live(): %s\n", errBuf);  
      exit(1);  
    }  
    
    /*以下三行的注释去掉，则开启包过滤功能*/  
    //struct bpf_program filter; //bpf_program结 构的指针,用于pcap_compile，格式过滤
    //pcap_compile(device, &filter, "dst port 23", 1, 0); //编译 BPF 过滤规则 
    //pcap_compile(device, &filter, "arp", 1, 0); //编译 BPF 过滤规则 
    //pcap_setfilter(device, &filter); //应用 BPF 过滤规则 
      
    int id = 0; 
  
    /* pcap_loop(网卡的指针,设置所捕获数据包的个数,回调函数,留给用户使用的)；
     * 如果设置所捕获数据包的个数为-1，则无限循环捕获；
     * 循环捕获网络数据包，直到遇到错误或者满足退出条件；
     * 每次捕获一个数据包就会调用 callback 指定的回调函数(此处为getPacket)
     * pcap_loop的最后一个参数user是留给用户使用的，当callback被调用的时候这个值会传递给callback的第一个参数(也叫user)
     */
    pcap_loop(device, -1, getPacket, (u_char*)&id);  
      
    pcap_close(device); //释放网络接口 
    
    return 0;  
}  

