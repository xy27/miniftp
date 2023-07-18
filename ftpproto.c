#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"
#include <signal.h>

void ftp_lreply(session_t *sess, int status, const char *text);

int get_port_fd(session_t *sess);
int get_pasv_fd(session_t *sess);

int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);
int pasv_active(session_t *sess);

int list_common(session_t *sess, int detail);
void upload_common(session_t *sess, int is_append);
void limit_rate(session_t *sess, int bytes_transfered, int is_upload);

void start_cmdio_alarm();
void start_data_alarm();
void check_abor(session_t *sess);

static void do_user(session_t *sess);	// *
static void do_pass(session_t *sess);	// *
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);	// *
static void do_pasv(session_t *sess);	// *
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);	// *
static void do_stor(session_t *sess);	// *
static void do_appe(session_t *sess);	// *
static void do_list(session_t *sess);	// *
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);	// *
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);	// ???
static void do_rnto(session_t *sess);	// ???
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);

typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;

static ftpcmd_t ctrl_cmds[] = {
	// 访问控制命令
	{"USER",	do_user	},
	{"PASS",	do_pass	},
	{"CWD",		do_cwd	},
	{"XCWD",	do_cwd	},
	{"CDUP",	do_cdup	},
	{"XCUP",	do_cdup	},
	{"QUIT",	do_quit	},
	{"ACCT",	NULL	},
	{"SMNT",	NULL	},
	{"REIN",	NULL	},

	// 传输参数命令
	{"PORT",	do_port	},
	{"PASV",	do_pasv	},
	{"TYPE",	do_type	},
	{"STRU",	do_stru	},
	{"MODE",	do_mode	},

	// 服务命令
	{"RETR",	do_retr	},
	{"STOR",	do_stor	},
	{"APPE",	do_appe	},
	{"LIST",	do_list	},
	{"NLST",	do_nlst	},
	{"REST",	do_rest	},
	{"ABOR",	do_abor	},
	{"\377\364\377\362ABOR", do_abor},
	{"PWD",		do_pwd	},
	{"XPWD",	do_pwd	},
	{"MKD",		do_mkd	},
	{"XMKD",	do_mkd	},
	{"RMD",		do_rmd	},
	{"XRMD",	do_rmd	},
	{"DELE",	do_dele	},
	{"RNFR",	do_rnfr	},
	{"RNTO",	do_rnto	},
	{"SITE",	do_site	},
	{"SYST",	do_syst	},
	{"FEAT",	do_feat },
	{"SIZE",	do_size	},
	{"STAT",	do_stat	},
	{"NOOP",	do_noop	},
	{"HELP",	do_help	},
	{"STOU",	NULL	},
	{"ALLO",	NULL	}
};
void handle_sigpipe(int signum)
{
	printf("receive a signal %d\n", signum);
}

session_t *p_sess;	// 在main.c中被赋值

// 控制连接空闲超时的信号处理函数
void handle_alarm_timeout(int signum)
{
	shutdown(p_sess->ctrl_fd, SHUT_RD);
	ftp_reply(p_sess, FTP_IDLE_TIMEOUT, "Timeout");
	shutdown(p_sess->ctrl_fd, SHUT_WR);
	exit(EXIT_FAILURE);
}

// 数据连接通道相关的信号处理函数
void handle_sigalarm(int signum)
{
	// 当前不处于数据传输状态(这里其实是创建了数据连接，但是没有进行数据(文件)传输)
	if (!p_sess->data_process)  // data_process 只有在limit_rate才被设置为1,即只有传输文件的时候才会置为1
	{
		ftp_reply(p_sess, FTP_DATA_TIMEOUT, "Data timeout. Reconnect. Sorry.");
		exit(EXIT_FAILURE);
	}

	// 否则，当前处于数据(文件)传输的状态，收到了超时信号
	p_sess->data_process = 0; // 这里的逻辑感觉不是那么正确，合理，data_process什么时候被设置为1的？？？limit_rate中会设置为1
	start_data_alarm();
}

void handle_sigurg(int sigunm)
{
	// 当前没有处于数据传输状态
	// 如果服务进程没有处于数据传输，
	// 这个时候应该是在等待客户端的命令,abor命令是通过控制连接来接受的，执行do_abor
	if (p_sess->data_fd == -1)
	{
		return;
	}
	// 接收带外数据
	char cmdline[MAX_COMMAND_LINE] = {0};
	int ret = readline(p_sess->ctrl_fd, cmdline, MAX_COMMAND_LINE);		// 从控制连接中读取命令

	if (ret <= 0)
	{
		ERR_EXIT("readline");
	}

	str_trim_crlf(cmdline);
	if (strcmp(cmdline, "ABOR") == 0 ||
		strcmp(cmdline, "\377\364\377\362ABOR") == 0)
	{
		p_sess->abor_received = 1;
		shutdown(p_sess->data_fd, SHUT_RDWR); // 直接关闭数据连接,如果ftp服务进程处于read,write,则会返回-1,
	}										  // 如果处于限速睡眠状态，则需要随后判断是否接收到abor
	else
	{
		ftp_reply(p_sess, FTP_BADCMD, "Unknown command");
	}
}

void start_cmdio_alarm()
{
	if (tunable_idle_session_timeout > 0)
	{
		signal(SIGALRM, handle_alarm_timeout);
		alarm(tunable_idle_session_timeout);
	}
}

void start_data_alarm()
{
	if (tunable_data_connection_timeout > 0)
	{
		// 安装数据连接通道相关的信号、闹钟
		signal(SIGALRM, handle_sigalarm);
		alarm(tunable_data_connection_timeout);
	}
	else if (tunable_idle_session_timeout > 0)
	{
		// 关闭之前安装的闹钟,这是指控制连接相关的闹钟
		alarm(0);
	}
}

void check_abor(session_t *sess)
{
	if (sess->abor_received == 1)
	{
		sess->abor_received = 0; // 这个状态要重新置为0，否则会一直处于接收到abor的状态，是不正确的
		ftp_reply(p_sess, FTP_ABOROK, "ABOR successful.");
	}
}


void handle_child(session_t *sess)
{
	ftp_reply(sess, FTP_GREET, "(miniftpd 0.1).");
	int ret;
	while (1)
	{
		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));

		start_cmdio_alarm();
		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		printf("in handle_child ret=%d\n", ret);
		if (ret == -1)
			ERR_EXIT("readline");
		else if (ret == 0)
			exit(EXIT_SUCCESS);

		str_trim_crlf(sess->cmdline);					// 去除\r\n				
		printf("cmdline=[%s]\n", sess->cmdline);

		// 解析FTP命令与参数
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');	// arg是怎么被存储的？有多个arg呢？
		printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
		str_upper(sess->cmd);									// 将命令转换为大写

		// 处理FTP命令
		int i;
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
		for (i=0; i<size; ++i)
		{
			if (strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)
			{
				if (ctrl_cmds[i].cmd_handler != NULL)
				{
					ctrl_cmds[i].cmd_handler(sess);
				}
				else 
				{
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				}
				
				break;
			}
		}		
		if (i == size)
		{
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
		}
	}
}

void ftp_reply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

void ftp_lreply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

int list_common(session_t *sess, int detail)
{
	DIR *dir = opendir(".");
	if (dir == NULL)
	{
		return 0;
	}

	struct dirent *dt;
	struct stat sbuf;
	while ((dt = readdir(dir)) != NULL)
	{
		if (lstat(dt->d_name, &sbuf) < 0)
		{
			continue;
		}
		if (dt->d_name[0] == '.')
		{
			continue;
		}

		char buf[1024] = {0};
		if (detail)
		{
			const char *perms = statbuf_get_perms(&sbuf);
	
			int off = 0;
			off += sprintf(buf, "%s ", perms);
			off += sprintf(buf+off, "%3lu %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			off += sprintf(buf+off, "%8lu ", (unsigned long)sbuf.st_size);
	
			const char *datebuf = statbuf_get_date(&sbuf);
	
			off += sprintf(buf+off, "%s ", datebuf);
			if (S_ISLNK(sbuf.st_mode))
			{
				char tmp[1024] = {0};
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf+off, "%s -> %s\r\n", dt->d_name, tmp);
			}
			else
			{
				off += sprintf(buf+off, "%s\r\n", dt->d_name);
			}
		}
		else
		{
			sprintf(buf, "%s\r\n", dt->d_name);
		}

		int ret = writen(sess->data_fd, buf, strlen(buf));
		if (ret == -1)
			perror("writen");
	}
		
	closedir(dir);
	return 1;
}

void limit_rate(session_t *sess, int bytes_transfered, int is_upload)
{
	sess->data_process = 1;		// 表示当前正在传输数据
	
	// 睡眠时间 = (当前传输速度 / 最大传输速度 - 1) * 当前传输时间
	long curr_sec = get_time_sec();
	long curr_usec = get_time_usec();

	double elapsed;
	elapsed = (double)(curr_sec - sess->bw_transfer_start_sec);
	elapsed += (double)(curr_usec - sess->bw_transfer_start_usec) / (double)(1000*1000);
	if (elapsed <= (double)0)
	{
		elapsed = (double)0.01;
	}
	// assert(elapsed >= 0);

	// 计算当前传输速度
	// unsigned int bw_rate = (unsigned int)((double)bytes_transfered / elapsed);
	unsigned long long bw_rate = (unsigned long long)((double)bytes_transfered / elapsed);

	double rate_ratio;
	if (is_upload)
	{
		// printf("upload_rate=%d max_rate=%d\n", bw_rate, sess->bw_upload_rate_max);
		// printf("upload_rate=%llu max_rate=%d\n", bw_rate, sess->bw_upload_rate_max);
		if (bw_rate <= sess->bw_upload_rate_max)
		{
			// 不需要限速
			// sess->bw_transfer_start_sec = curr_sec;
			// sess->bw_transfer_start_usec = curr_usec;
			sess->bw_transfer_start_sec = get_time_sec();
			sess->bw_transfer_start_usec = get_time_usec();
			return;
		}
		rate_ratio = bw_rate / sess->bw_upload_rate_max;
	}
	else
	{
		// printf("download_rate=%d max_rate=%d\n", bw_rate, sess->bw_download_rate_max);
		// printf("download_rate=%llu max_rate=%d\n", bw_rate, sess->bw_download_rate_max);
		if (bw_rate <= sess->bw_download_rate_max)
		{
			// 不需要限速
			//sess->bw_transfer_start_sec = curr_sec;
			//sess->bw_transfer_start_sec = curr_sec;
			sess->bw_transfer_start_usec = get_time_sec();
			sess->bw_transfer_start_usec = get_time_usec();
			return ;
		}
		rate_ratio = bw_rate / sess->bw_download_rate_max;
	}

	// 睡眠时间 = (当前传输速度 / 最大传输速度 - 1) * 当前传输时间
	double pause_time = (rate_ratio - 1) * elapsed;
	nano_sleep(pause_time);
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();
}

void upload_common(session_t *sess, int is_append)
{
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}	

	long long offset = sess->restart_pos;
	sess->restart_pos = 0;

	// 打开文件
	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);
	if (fd == -1)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}
	int ret;
	// 加写锁
	ret = lock_file_write(fd);			// 防止同时写同一个文件，或同时读写同一个文件
	if (ret == -1)
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	// STOR 			上传
	// REST+STOR		断点续传
	// APPE				也是断点续传
	if (!is_append && offset == 0)		// STOR
	{
		ftruncate(fd, 0);
		if (lseek(fd, 0, SEEK_SET) < 0)
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}
	else if (!is_append && offset != 0)	// REST+STOR
	{
		if (lseek(fd, offset, SEEK_SET) < 0)
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}	
	}
	else if (is_append)					// APPE
	{
		if (lseek(fd, 0, SEEK_END) < 0)
		{
			ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
			return;
		}
	}

	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_UPLOADFAIL, "Could not create file.");
		return;
	}

	// 150
	char text[2048] = {0};
	if (sess->is_ascii)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%ld bytes).", sess->arg, sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%ld bytes).", sess->arg, sbuf.st_size);
	}
	ftp_reply(sess, FTP_DATACONN, text);

	// 我们实际是以二进制方式传输文件,不支持ascii模式
	// 上传文件 
	int flag = 0;
	// char buf[256];
	char buf[512];				// 发现一个有趣的现象，buf设置太大，限速会功能会不正常(没有用)，是不是和一次请求read socket数据太多有关？
								// 下载的时候，好像这个现象不是很明显(把buf大小改为65536也不明显)，把sendfile换成read，write也不明显
	// char buf[1024];
	// char buf[4096];
	// char buf[65536];			// buf的大小设为多少比较合适

	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	while (1)
	{
		ret = read(sess->data_fd, buf, sizeof(buf));	// 直接用read，没用什么readn，没必要
		// ret = sendfile(fd, sess->data_fd, NULL, 4096); // error，in_fd cannot be a socket
		if (ret == -1)
		{
			if (errno == EINTR)
				continue;
			else
			{
				perror("sendfile");
				flag = 1;
				break;
			}
		}
		else if (ret == 0)
		{
			flag = 0;
			break;
		}

		limit_rate(sess, ret, 1);
		if (sess->abor_received == 1)
		{
			flag = 2;
			break;
		}

		if (writen(fd, buf, ret) != ret)
		{
			flag = 2;
			break;
		}
	}

	// 关闭数据连接
	close(sess->data_fd);
	sess->data_fd = -1;
	close(fd);

	if (flag == 0 && !sess->abor_received)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");	
	}
	else if (flag == 1)
	{
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from network stream.");	
	}
	else if (flag == 2)
	{
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to local file.");	
	}	
	check_abor(sess);
}

// 是否是port模式
int port_active(session_t *sess)
{
	if (sess->port_addr)
	{
		if (pasv_active(sess))
		{
			fprintf(stderr, "both port and pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}	
	return 0;
}

// 是否是pasv模式
int pasv_active(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	int active = priv_sock_get_int(sess->child_fd);
	if (active)
	{
		if (port_active(sess))	// 事实上，如果既是port又是pasv,这样的逻辑判断会无限递归
		{
			fprintf(stderr, "both port and pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

// port模式，主动发起连接，成功返回1，失败返回0
int get_port_fd(session_t *sess)
{
	// 向nobody进程发送PRIV_SOCK_GET_DATA_SOCK命令
	// 向nobody发送一个整数port
	// 向nobody发送一个字符串
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
	unsigned short port = ntohs(sess->port_addr->sin_port);
	char *ip = inet_ntoa(sess->port_addr->sin_addr);
	priv_sock_send_int(sess->child_fd, (int)port);
	priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

	char res = priv_sock_get_result(sess->child_fd);
	if (res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	else if (res == PRIV_SOCK_RESULT_BAD)
	{
		return 0;
	}	
	return 1;
}

// pasv模式，接收客户端发起的连接，成功返回1，失败返回0
int get_pasv_fd(session_t *sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	char res = priv_sock_get_result(sess->child_fd);
	if (res == PRIV_SOCK_RESULT_BAD)
	{
		return 0;
	}
	else if (res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
	}
	return 1;
}

// 获取数据连接 sockfd,成功返回1，失败返回0
int get_transfer_fd(session_t *sess)
{
	// 检测是否收到PORT命令或者PASV命令
	if (!port_active(sess) && !pasv_active(sess))
	{
		ftp_reply(sess, FTP_BADSENDCONN, "Use RORT or PASV first");		
		return 0;
	}

	int ret = 1;
	// 如果是主动模式
	if (port_active(sess))
	{
		if (get_port_fd(sess) == 0)
		{
			ret = 0;
		}
	}
	if (pasv_active(sess))
	{
		if (get_pasv_fd(sess) == 0)
		{
			ret = 0;
		}
	}
	if (sess->port_addr)
	{
		free(sess->port_addr);
		sess->port_addr = NULL;
	}
	if (ret == 1)
	{
		// 重新安装SIGALRM信号，并启动闹钟
		start_data_alarm();
	}
	return ret; 
}

static void do_user(session_t *sess)
{
	// USER b52
	struct passwd *pw = getpwnam(sess->arg);
	if (pw == NULL)
	{
		// 用户不存在
		ftp_reply(sess, FTP_LOGINERR, "1 Login incorrect."); 
		return;
	}		
	sess->uid = pw->pw_uid;
	ftp_reply(sess, FTP_GIVEPWORD, "please specify the passwd.");	
}

static void do_pass(session_t *sess)
{
	// PASS 123456
	struct passwd *pw = getpwuid(sess->uid);
	if (pw == NULL)
	{
		// 用户不存在
		ftp_reply(sess, FTP_LOGINERR, "2 Login incorrect."); 
		return;
	}
	
	printf("name=[%s]\n", pw->pw_name);
	struct spwd *sp = getspnam(pw->pw_name);	// sp shadow passwd /etc/shadow
	if (sp == NULL)
	{
		// 用户不存在
		ftp_reply(sess, FTP_LOGINERR, "3 Login incorrect."); 
		return;
	}
 
	// 将明文进行加密
	char *encrypted_pass = crypt(sess->arg, sp->sp_pwdp);	// 这个函数的用法不知道
	// 验证密码
	if (strcmp(encrypted_pass, sp->sp_pwdp) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "4 Login incorrect."); 
		return;
	}

	signal(SIGURG, handle_sigurg);
	activate_sigurg(sess->ctrl_fd);

	umask(tunable_local_umask);

	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);

	chdir(pw->pw_dir);
	ftp_reply(sess, FTP_LOGINOK, "5 Login successful.");
}

static void do_cwd(session_t *sess)
{
	if (chdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return ;
	}
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_cdup(session_t *sess)
{
	if (chdir("..") < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return ;
	}
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_quit(session_t *sess)
{
	ftp_reply(sess, FTP_GOODBYE, "Goodbye.");
	exit(EXIT_SUCCESS);
}

static void do_port(session_t *sess)
{
	// PORT 192,168,10,28,123,23(客户端发过来的IP地址，监听端口)
	unsigned int v[6];

	// 每一次客户端发port命令，相应的监听端口可能每次都是不一样的
	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
	sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));		// 需要自己分配内存，什么时候释放？？？
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	sess->port_addr->sin_family = AF_INET;	// 地址一定要正确初始化

	// 注意点分十进制的由来
	unsigned char *p = (unsigned char *)&sess->port_addr->sin_addr;
	p[0] = v[0];
	p[1] = v[1];
	p[2] = v[2];
	p[3] = v[3];

	p = (unsigned char *)&sess->port_addr->sin_port;
	p[0] = v[4];
	p[1] = v[5];

	printf("ip=%s port=%u\n", inet_ntoa(sess->port_addr->sin_addr), ntohs(sess->port_addr->sin_port));
	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess)
{
	// Entering  Passive Mode (192,168,0,102,243,169)
	char ip[16] = {0};
	getlocalip(ip);		// 获取本机IPv4地址，比如，192.168.3.180(内网地址)

	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	unsigned short port = priv_sock_get_int(sess->child_fd);	// 本机字节序

	printf("port=%d\n", port);

	unsigned int v[4];
	sscanf(ip, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u)", v[0], v[1], v[2], v[3], port>>8, port&0xff);
	
	ftp_reply(sess, FTP_PASVOK, text);
}

static void do_type(session_t *sess) 
{
	if (strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if (strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else 
	{
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}
}

static void do_stru(session_t *sess)
{
}

static void do_mode(session_t *sess)
{
}

static void do_retr(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}

	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	
	// 打开文件
	int fd = open(sess->arg, O_RDONLY);
	if (fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	int ret;
	// 加读锁
	ret = lock_file_read(fd);		// 可以同时读同一个文件，但是读的时候，不能写该文件
	if (ret == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	// 判断是否时普通文件
	struct stat sbuf;
	ret = fstat(fd, &sbuf);
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
		return;
	}

	if (offset != 0)
	{
		ret = lseek(fd, offset, SEEK_SET);
		if (ret == -1)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to open file.");
			return;
		}
	}

	// 150
	char text[2048] = {0};
	if (sess->is_ascii)
	{
		sprintf(text, "Opening ASCII mode data connection for %s (%ld bytes).", sess->arg, sbuf.st_size);
	}
	else
	{
		sprintf(text, "Opening BINARY mode data connection for %s (%ld bytes).", sess->arg, sbuf.st_size);
	}

	ftp_reply(sess, FTP_DATACONN, text);

	// 我们实际是以二进制方式传输文件,不支持ascii模式
	// 下载文件
	int flag = 0;
	long long bytes_to_send = sbuf.st_size;
	if (offset > bytes_to_send)		// 这是什么情况？？？
	{
		bytes_to_send = 0;
	}
	else
	{
		bytes_to_send -= offset;
	}

	// 获取传输开始的时间
	sess->bw_transfer_start_sec = get_time_sec();
	sess->bw_transfer_start_usec = get_time_usec();

	// char buf[4096] = {0};
	while (bytes_to_send)
	{
		int num_this_time = bytes_to_send > 4096 ? 4096 : bytes_to_send;
		ret = sendfile(sess->data_fd, fd, NULL, num_this_time);
		if (ret == -1)
		{
			flag = 2;
			break;
		}

		limit_rate(sess, ret, 0);
		if (sess->abor_received == 1)
		{
			flag = 2;
			break;
		}
		bytes_to_send -= ret;
	}

	if (bytes_to_send == 0)
	{
		flag = 0;
	}

	// 关闭数据连接
	close(sess->data_fd);
	sess->data_fd = -1;

	close(fd);

	if (flag == 0 && !sess->abor_received)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");	
	}
	else if (flag == 1)
	{
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading from local file.");	
	}
	else if (flag == 2)
	{
		ftp_reply(sess, FTP_BADSENDNET, "Failure writting to network stream.");	
	}

	check_abor(sess);
}

static void do_stor(session_t *sess)
{
	upload_common(sess, 0);
}

static void do_appe(session_t *sess)
{
	upload_common(sess, 1);
}

static void do_list(session_t *sess)
{
	if (get_transfer_fd(sess) == 0)		// 创建数据连接
	{
		return ;
	}
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
	list_common(sess, 1);		// 传输列表
	close(sess->data_fd); 		// 关闭数据套接字，可以用tcpdump看看连接关闭的过程，直接close没有问题吗？
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

static void do_nlst(session_t *sess)
{
	if (get_transfer_fd(sess) == 0)
	{
		return ;
	}
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");
	list_common(sess, 0);
	close(sess->data_fd);
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

static void do_rest(session_t *sess)
{
	sess->restart_pos = str_to_longlong(sess->arg);
	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}

static void do_abor(session_t *sess)
{
	ftp_reply(sess, FTP_ABOR_NOCONN, "No transfer to ABOR");
}

static void do_pwd(session_t *sess)
{
	char dir[1024+1] = {0};
	char text[1024+50] = {0};
	getcwd(dir, 1024);
	sprintf(text, "\"%s\" is the current directory", dir);
	ftp_reply(sess, FTP_PWDOK, text);
}

static void do_mkd(session_t *sess)
{
	if (mkdir(sess->arg, 0777) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
		return ;
	}
	char text[4096] = {0};
	if (sess->arg[0] == '/')
	{
		sprintf(text, "%s created", sess->arg);
	}
	else
	{
		char dir[2048+1] = {0};
		getcwd(dir, 2048);
		if (dir[strlen(dir)-1] == '/')
		{
			sprintf(text, "%s%s created", dir, sess->arg);
		}
		else
		{
			sprintf(text, "%s/%s created", dir, sess->arg);
		}
	}
	ftp_reply(sess, FTP_MKDIROK, text);
}

static void do_rmd(session_t *sess)
{
	if (rmdir(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
		return;
	}
	ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successfuk");
}

static void do_dele(session_t *sess)
{
	if (unlink(sess->arg) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Delete operation failed.");
		return;
	}	
	ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

static void do_rnfr(session_t *sess)
{
	sess->rnfr_name = (char *)malloc(strlen(sess->arg)+1);
	memset(sess->rnfr_name, 0, strlen(sess->arg)+1);
	strcpy(sess->rnfr_name, sess->arg);
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO");
}

static void do_rnto(session_t *sess)
{
	if (sess->rnfr_name == NULL)
	{
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}
	
	rename(sess->rnfr_name, sess->arg);
	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");

	free(sess->rnfr_name);
	sess->rnfr_name = NULL;
}

static void do_site(session_t *sess)
{
}

static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

static void do_feat(session_t *sess)
{
	ftp_lreply(sess, FTP_FEAT, "Features:");
	writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"));
	writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
	writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
	ftp_reply(sess, FTP_FEAT, "End");
}

static void do_size(session_t *sess)
{
	struct stat sbuf;
	if (stat(sess->arg, &sbuf) < 0)
	{
		ftp_reply(sess, FTP_FILEFAIL, "SIZE operation failed.");
		return;
	}	
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}
	char text[1024] = {0};
	sprintf(text, "%ld", sbuf.st_size);
	ftp_reply(sess, FTP_SIZEOK, text);
}

static void do_stat(session_t *sess)
{
}

static void do_noop(session_t *sess)
{
	ftp_reply(sess, FTP_NOOPOK, "NOOP ok.");
}

static void do_help(session_t *sess)
{
}
