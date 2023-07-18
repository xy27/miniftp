#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"

typedef struct session
{
	// 控制连接
	uid_t uid;
	int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
	
	// 为什么要这么设计？？？
	// 为什么port模式下，不存储客户端的listen fd, 因为port模式下，客户端发给服务端的是IP地址以及端口号
	// 为什么pasv模式下，不存储服务器端的监听套接字地址？没有必要，存储相应的listenfd就可以了
	// 可以利用数据连接相关的一些字段，来判断当前数据连接采用的是什么模式

	// 数据连接
	struct sockaddr_in *port_addr;		// port模式下，客户端的监听套接字地址，注意这是一个指针
	int pasv_listen_fd;					// pasv模式下，服务器端的监听套接字
	int data_fd;
	int data_process;					// 是否处于数据传输状态

	// 限速
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;

	// 父子进程通道
	int parent_fd;
	int child_fd;
	
	// FTP协议状态
	int is_ascii;
	long long restart_pos;		// REST命令设置了这个参数，和断点续传，续载有关
	char *rnfr_name;
	int abor_received;

	// 连接数限制
	unsigned int num_clients;	// 当前连接到服务器的用户数（控制连接数），其实这并不是会话的属性
	unsigned int num_this_ip;	// 该会话所对应的客户端IP,当前所请求的连接数
} session_t;

void begin_session(session_t *sess);


#endif /*_SESSION_H_*/
