#include "common.h"
#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"
//#include <signal.h>
	
void begin_session(session_t *sess)
{
	activate_oobinline(sess->ctrl_fd);
	priv_sock_init(sess);	// 构建nobody进程与服务进程之间的通信管道

	pid_t pid;
	pid = fork();
	if (pid == -1)
		ERR_EXIT("fork");
	if (pid == 0)  // 注意在父进程与子进程中，虽然sess地址是一样的，但是这个地址是各自进程空间的中的地址，不是指向同一块内存
	{			   // 但是这两个地址都可以正确访问各自的session_t变量
				   // 每一个子进程都会复制父进程的sess变量	
		// ftpd服务进程
		priv_sock_set_child_context(sess);
		handle_child(sess);
	}
	else
	{
		// nobody进程
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}
