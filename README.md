# ytp-client

the client of ytp-server.

***



.
├── client  
├── main.cpp  
├── makefile  
├── README.md  
├── ssl_util.cpp  
├── ssl_util.h  
├── test  
│   ├── 1.png  
│   ├── client  
│   ├── client.cpp  
│   ├── makefile  
│   └── test  
├── ytp.cpp  
└── ytp.h  

运行方法：make-->./client即可

ytp-client类似ftp-client，支持所有常用Linux命令解析，cd、ls、pwd用于查看远程定位，在前面加l就是本地命令，用lls、lpwd、lcd来定位本地定位。虽然命令解析主要用于文件定位，但是其他一些命令也支持使用。

getfile filename从服务器工作目录获取文件到本地工作目录，sendfile filename从本地工作目录发送文件到服务器工作目录。每次只能收发一个文件，否则会提示命令参数过多。

另外，连接启动时本地工作目录会切换到本地user的home，远端用户工作目录会切换到登录所用user的home，交互逻辑类似于ftp，请在收发前pwd、ls进行定位。