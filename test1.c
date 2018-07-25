#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>
#include <byteswap.h>
#include <stdarg.h>

#define BYTE_SWAP16(x) bswap_16(x)
#define BYTE_SWAP32(x) bswap_32(x)
#define BYTE_SWAP64(x) bswap_64(x)

#define MAX_HEXDUM_LINE 16

#define E10_6 1000000
static int gSaveMileage = 0;
static int gCurMileage =0;
//声明消息
 struct jt_packet_s
{
	unsigned short id;   //消息ID
		
	struct
	{
		unsigned short len:10;//消息体长度
		unsigned short etype:3; //数据加密方式
		unsigned short split:1;//分包
		unsigned short reserve:2; //保留
	}__attribute__((packed))attr;                   /*消息体属性*/
	unsigned char simno[6];//手机号
	unsigned short snum;   //消息流水号
	struct
	{
		unsigned short total;  //总包数
		unsigned short count;//包序号
	}__attribute__((packed))ext; //消息
};
struct jt_flag_s
{
	unsigned int acc:1;
	unsigned int loc:1;
	unsigned int lat:1;
	unsigned int lng:1;
	unsigned int operation:1;
	unsigned int enc:1;   //经纬度未经/已经保密插件保密
	unsigned int reserval:2;//保留
	unsigned int carry:2;  //00空车01半载10保留11满载
	unsigned int oil:1;
	unsigned int electric:1;
	unsigned int door_lock:1;
	unsigned int door1:1;
	unsigned int door2:1;
	unsigned int door3:1;
	unsigned int door4:1;
	unsigned int door5:1;
	unsigned int gps:1;
	unsigned int bd:1;
	unsigned int glonass:1;
	unsigned int galileo:1;
}__attribute__((packed));
struct jt_addition_s
{
	unsigned char id;
	unsigned char len;
	unsigned char *data;
};
 //大小端模式，拆包与解包
#if __BYTE_ORDER == __BIG_ENDIAN
int pack_be32(char *p, unsigned int val)
{
	*((unsigned int *)p) = val;
	return sizeof(unsigned int);
}

int unpack_be32(char *p, unsigned int *val)
{
	*val = *((unsigned int *)p);
	return sizeof(unsigned int);
}

int pack_be16(char *p, unsigned short val)
{
	*((unsigned short *)p) = val;
	return sizeof(unsigned short);
}

int unpack_be16(char *p, unsigned short *val)
{
	*val = *((unsigned short *)p);
	return sizeof(unsigned short);
}

int pack_le32(char *p, unsigned int val)
{
	*((unsigned int *)p) = BYTE_SWAP32(val);
	return sizeof(unsigned int);
}

int unpack_le32(char *p, unsigned int *val)
{
	*val = BYTE_SWAP32( *((unsigned int *)p) );
	return sizeof(unsigned int);
}

int pack_le16(char *p, unsigned short val)
{
	*((unsigned short *)p) = BYTE_SWAP16(val);
	return sizeof(unsigned short);
}

int unpack_le16(char *p, unsigned short *val)
{
	*val = BYTE_SWAP16( *((unsigned short *)p) );
	return sizeof(unsigned short);
}
#else
int pack_be32(char *p, unsigned int val)
{
	*((unsigned int *)p) = BYTE_SWAP32(val);
	return sizeof(unsigned int);
}

int unpack_be32(char *p, unsigned int *val)
{
	*val = BYTE_SWAP32( *((unsigned int *)p) );
	return sizeof(unsigned int);
}

int pack_be16(char *p, unsigned short val)
{
	*((unsigned short *)p) = BYTE_SWAP16(val);
	return sizeof(unsigned short);
}

int unpack_be16(char *p, unsigned short *val)
{
	*val = BYTE_SWAP16( *((unsigned short *)p) );
	return sizeof(unsigned short);
}

int pack_le32(char *p, unsigned int val)
{
	*((unsigned int *)p) = val;
	return sizeof(unsigned int);
}

int unpack_le32(char *p, unsigned int *val)
{
	*val = *((unsigned int *)p);
	return sizeof(unsigned int);
}

int pack_le16(char *p, unsigned short val)
{
	*((unsigned short *)p) = val;
	return sizeof(unsigned short);
}

int unpack_le16(char *p, unsigned short *val)
{
	*val = *((unsigned short *)p);
	return sizeof(unsigned short);
}
#endif

int unpack_str(char *p, char *str, int len)
{
	memset(str, 0, len);
	memcpy(str, p, len);
	return len;
}
int pack_u8(char *p, unsigned char val)
{
	*p=val;
	return sizeof(unsigned char);
}
int unpack_u8(char *p,unsigned char *val)
{
	*val = *p;
	return sizeof(unsigned char);
}

void hexdump_ascii(const char *buf, int len, char *fmt, ...)
{
	va_list ap;
	int  i, llen;
	const char *pos = buf;
	char line[1024] = {0};

	va_start(ap, fmt);
	vsprintf(line+strlen(line), fmt, ap);
	va_end(ap);

	if (buf == NULL || len <= 0) {
		printf("%s - hexdump_ascii(len:%d): [NULL]\n", line, len);
		return;
	}
	printf("%s - hexdump_ascii(len:%d):\n", line, len);
	while (len) {
		llen = len > MAX_HEXDUM_LINE ? MAX_HEXDUM_LINE : len;
		sprintf(line, "%08x:", pos-buf);
		for (i=0; i<llen; i++)   
			sprintf(line+strlen(line), " %02x", (unsigned char)pos[i]);
		for (   ; i<MAX_HEXDUM_LINE; i++)
			sprintf(line+strlen(line), "   ");
		strcat(line, "  ");
		for (i=0; i<llen; i++) {
			if (isprint(pos[i]))
				sprintf(line+strlen(line), "%c", pos[i]);
			else
				strcat(line, ".");
		}
		for (   ; i<MAX_HEXDUM_LINE; i++)
			strcat(line, " ");
		printf("%s\n", line);

		pos += llen;
		len -= llen;
	}
}

//解析头部
static int unpack_jt808_header(struct jt_packet_s *hdr,char *data)
{
	int ret = 0;
	unsigned short *attr = (unsigned short *)&hdr -> attr;
	
	ret += unpack_be16(data+ret, &hdr->id);
	ret += unpack_be16(data+ret, attr);

	memcpy(hdr -> simno, data+ret, sizeof(hdr -> simno));
	ret += sizeof(hdr -> simno);
	ret += unpack_be16(data + ret,&hdr -> snum);

	if(hdr -> attr.split)
	{
		ret += unpack_be16(data + ret,&hdr->ext.total);
		ret += unpack_be16(data + ret,&hdr->ext.count);
	}
	return ret;
}

/*static int unpack_jt808_header(struct jt_packet_s *hdr,char *data)
{
	int ret=0;
	unsigned short *attr=(unsigned short *)&hdr->attr;

	ret+=unpack_be16(data+ret,&hdr->id);
	ret+=unpack_be16(data+ret,attr);
		
	
}*/
//封装头
static int pack_jt808_header(struct jt_packet_s *hdr,char *data)
{
	int ret=0;
	unsigned short *attr = (unsigned short *)&hdr->attr;
	
	ret+=pack_be16(data+ret,hdr->id);
	ret+=pack_be16(data+ret,*attr);
	memcpy(data+ret, hdr->simno, sizeof(hdr->simno));
	ret+=sizeof(hdr->simno);
	ret+=pack_be16(data+ret,hdr->snum);
	
	if(hdr->attr.split)
	{
		ret+=pack_be16(data+ret,hdr->ext.total);
		ret+=pack_be16(data+ret,hdr->ext.count);
	}
	return ret;
}

//反转译
static int trans_packet_from(char *data,int len)
{
	int i,outlen = 0;

	for(i=0;i<len;i++) {
		if(data[i]==0x7d) {
			switch(data[++i]) {
				case 0x01:
					data[outlen++] = 0x7d;
			                 break;
				case 0x02:
					data[outlen++] = 0x7e;
					break;
				default:
					return -1;				
			}	
		} else {
			data[outlen++] = data[i];
		}
	}	
	return outlen;    //出错点
}
//转译
static int trans_packet_to(char *data,int len)
{
	//重要函数，memcpy()	
	int i,outlen; 
	char buf[2082] = {0};

	for(i=0; i<len; i++) {
		switch(data[i]) {
		case 0x7e:
			buf[outlen] = 0x7d;
			buf[outlen+1] = 0x02;
			outlen += 2;
			break;
		case 0x7d:
			buf[outlen] = 0x7d;
			buf[outlen+1] = 0x01;
			outlen += 2;
			break;
		default:
			buf[outlen] = data[i];
			outlen++;
			break;		
		}
	}
	memcpy(data,buf,outlen);//解释此句话意义：
}
//检测检验码
static char gen_check_code(char *data,int len)
{
	int i = 0;
	char ret = data[0];
	
	for(i=1;i<len;i++)
		ret=ret^data[i];
	return ret;
}

//清除头尾，得出数据实际长度
static int parse_packet_header(struct jt_packet_s *hdr,char *data,int len)
{
	char *rawdata=NULL;
	int hlen=0,dlen=0,tlen=0;   //头长，消息长，总长  局部变量注意初始化
	
	//检查数据长度是否异常
	if(len<15)
	{
		return -1;
	}
	//检查标识位是否异常
	if(data[0] != 0x7e||data[len-1] != 0x7e)
	{
		return -1;
	}
	rawdata = data+1;
	len = len-2;
	
	//反转译,得出实际总长度，即转译前的长度
       	tlen = trans_packet_from(rawdata, len);	        //
	printf("====tlen:%d\n", tlen);
	//检测检验码
	if((rawdata[tlen-1]) != (gen_check_code(rawdata, tlen-1)))
	{
		printf("=====check failed, gen code is:%02x\n", gen_check_code(rawdata, tlen-1));
		return -1;
	}
	tlen -= 1;
	//头文件长度
	hlen = unpack_jt808_header(hdr, rawdata);	//计算头文件的函数
	dlen = tlen-hlen;	

        memcpy(data,rawdata+hlen, dlen);
		
	return dlen;
} 
static void print_0x0200_alarm(unsigned int alarm)
{
	int i = 0;
	printf("alarm:(");
	for(i=0; i<32; i++){
		if(((alarm>>i)&0x01) == 0){
			continue;		
		}
		switch (i){
			case 1:
				printf("紧急报警\n");
				break;
			case 2:
				printf("超速报警\n");
				break;
			case 3:
				printf("疲劳驾驶\n");
				break;
			case 4:
				printf("危险预警\n");
				break;
			case 5:
				printf("GNSS模块故障\n");
				break;
			case 6:
				printf("GNSS天线未接或被剪断\n");
				break;
			case 7:
				printf("GNSS天线短路\n");
				break;
			case 8:
				printf("终端主电源欠压\n");
				break;
			case 9:
				printf("终端主电源掉电\n");
				break;
			case 10:
				printf("终端显示器故障\n");
				break;
			case 11:
				printf("TTS模块故障\n");
				break;
			case 12:
				printf("摄像头故障\n");
				break;
			case 13:
				printf("道路运输证IC卡模块故障\n");
				break;
			case 14:
				printf("超速预警\n");
				break;
			case 31:
				printf("非法开门报警");
				break;
		}		
		
	}
	printf(")\n");
}
static void print_0x0200_state(unsigned int* state_flag)
{
        struct jt_flag_s *pstate=NULL;

//	struct jt_flag_s *pstate=(struct jt_flag_s *)&state_flag;
        pstate = (struct jt_flag_s *)state_flag;
	if(pstate->acc){
		printf("ACC:on\n");
	}else {
		printf("ACC:off\n");
	}
	if(pstate->loc){
		printf("LOC:定位\n");
	}else{
		printf("LOC:未定位\n");
	}
	if(pstate->lat){
		printf("LAT:南纬\n");
	}else{
		printf("LAT:北纬\n");
	}
	switch(pstate -> carry){
		case 0:
			printf("空车\n");
			break;
		case 1:
			printf("半载\n");
			break;
		case 2:
			printf("保留\n");
			break;
		case 3:
			printf("满载\n");
			break;
	}
}
static print_lat_0200(int lat_flag)
{
//	unsigned int* lat = NULL;
//	printf("纬度:%d\n", lat_flag);
//	30759104 ==>  30.759104
	printf("纬度=%d.%d\n",lat_flag/E10_6,lat_flag%E10_6);
}
static print_lnt_0200(int lnt_flag)
{
//	unsigned int* lnt =NULL;
        printf("经度=%d.%d\n",lnt_flag/E10_6,lnt_flag%E10_6);
}
static print_het_0200(unsigned short het_flag)
{
	printf("高度=%d\n", het_flag);
}
static print_jt808_header(struct jt_packet_s *hdr )
{
	printf("msg id:%04x\n", hdr->id);
	printf("attr:%d\n", hdr->attr.len);
}
static print_spd_0200(unsigned short spd)
{
	printf("速度：%d\n",spd);
}
static print_tim_0200(unsigned char *tim)
{
	printf("时间：%x-%x-%x  %x:%x:%x\n",tim[0],tim[1],tim[2],tim[3],tim[4],tim[5]);
}
static print_drc_0200(unsigned short drc)
{
	printf("方向：%d\n",drc);
}
static print_addition_mileage(unsigned int mile)
{
	printf("里程：%d\n",mile);
}
static int get_vdr_cur_mileage()
{
	return gSaveMileage + gCurMileage;
}
static int unpack_addition_mileage(char *data)
{
	unsigned int ret = 0;
//	unsigned int mileage = get_vdr_cur_mileage()/100;
	unsigned int mileage = 0;

	ret += pack_u8(data+ret, 0x01);
	ret += pack_u8(data+ret, 4);
	ret += pack_u8(data+ret, mileage);

	return ret;
}

static void print_addition_id(unsigned char id)
{
     printf("id:%02x\n",id);	
}
static void print_addition_dlen(unsigned char dlen)
{
     printf("dlen:%d\n",dlen);
}


static void unpack_addition_info(char *data, int len)
{

}
unsigned char data_pack(unsigned char id, unsigned char len, unsigned char * data)
{
	int lc = 0;
	int ret = 0;
        switch(id)
	{
 	case 0x01:
		printf("%02x", data[0]);
//		unpack_be32(data, &lc);
//		lc =*(unsigned int *)data;
		printf("里程：%d\n",lc);			  
		return len;
	default:
		break;
	}	
	return 0;
}

static void dump_jt808_0200(char *data,int len)
{
	int ret = 0;
	unsigned int alarm = 0,state_flag = 0,lat_flag = 0,lnt_flag=0;
	unsigned short het_flag = 0, spd = 0,drc = 0;
	unsigned char tim[6] = {0};
        unsigned char mile,id = 0,dlen = 0;
      	struct jt_addition_s *pstate;
        int i=0;
	ret += unpack_be32(data+ret, &alarm);           //搞明白这个函数的含义
        //后四个字节数据解析点
	print_0x0200_alarm(alarm);
	ret += unpack_be32(data+ret, &state_flag);       
	//print_0x0200_alarm(alarm);
        print_0x0200_state(&state_flag); 
	ret += unpack_be32(data+ret, &lat_flag);
	print_lat_0200(lat_flag); 
	ret += unpack_be32(data+ret, &lnt_flag);
	print_lnt_0200(lnt_flag); 
	ret += unpack_be16(data+ret, &het_flag);
	print_het_0200(het_flag);
	ret += unpack_be16(data+ret, &spd);
	print_spd_0200(spd);
	ret += unpack_be16(data+ret, &drc);
	print_drc_0200(drc);
//	ret += sizeof(tim[6]);
	ret += unpack_str(data+ret, tim, 6);
	printf("打印2：%d\n",ret); 
	print_tim_0200(tim);
	//附加信息
/*	ret += unpack_u8(data+ret, &id);
	print_addition_id(id);
	ret += unpack_u8(data+ret, &dlen);
	print_addition_dlen(dlen);
	ret += unpack_str(data+ret, &mile, 4); 
 	print_addition_mileage(mile); */
	printf("%02x\n",data);
	unsigned char aid, alen, adata[8];
	while (ret < len) {
		ret += unpack_u8(data+ret, &aid);
		ret += unpack_u8(data+ret, &alen);
		ret += unpack_str(data+ret, adata, alen);
		printf("id:%02x len:%d data:", aid, alen);
		int ii;
		for (ii=0; ii<alen; ii++) {
			printf("%02x", adata[ii]);
		 }
		 printf("\n"); 
               }
}


       //	len = 0;
//	for(i = 0;i < 1;i++){
        /*	pstate = (struct jt_addition_s *)&data[ret + len];
       		len = data_pack(pstate->id, pstate->len, pstate->data);
		printf("=========id: %02x %02x len:%d \n",pstate->id,data[0],pstate->len);*/
/*		ret += unpack_u8(data + ret, pstate->);
		printf("id: %02x\n", );
		ret += unpack_u8(data + ret, ); ret += unpack_str(data+ret, &mile,  ); } #endif
 } */
static int dump_jt808_packet(struct jt_packet_s *hdr,char *data,int len) 
{    
	switch(hdr->id){
	case 0x0200:
		dump_jt808_0200(data, len);
		break; 
	}	
	return 0;
}
int main(int argc,char **argv)
{
	char data[] = {
		0x7e, 0x02, 0x00, 0x00, 0x53, 0x01, 0x30, 0x07, 0x06, 0x61, 0x73, 0x0f, 0x42, 0x80, 0x00, 0x00,
		0x00, 0x00, 0x0c, 0x00, 0x03, 0x01, 0xd2, 0x0e, 0x8e, 0x06, 0x33, 0xcf, 0xc4, 0x01, 0xf8, 0x00,
		0x00, 0x00, 0x00, 0x17, 0x11, 0x20, 0x07, 0x36, 0x48, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x02, 0x00, 0x00, 0x25, 0x04, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x04, 0x00, 0x00, 0x00, 0x01, 0x30,
		0x01, 0x63, 0x31, 0x01, 0x09, 0x14, 0x04, 0x00, 0x00, 0x00, 0x41, 0x15, 0x04, 0x00, 0x00, 0x00,
		0x07, 0x16, 0x04, 0x00, 0x00, 0x00, 0x00, 0x17, 0x02, 0x00, 0x00, 0x18, 0x03, 0x00, 0x00, 0x00,
		0x41, 0x7e
	};

	int ret = 0;
	struct jt_packet_s hdr; 
	ret=parse_packet_header(&hdr, data, sizeof(data));   //分析数据包，得到实际数据长度
       	print_jt808_header(&hdr);
	dump_jt808_packet(&hdr, data, ret);            //根据消息ID选择对应内容分析数据
	return 0;
}
/* 
 * */
