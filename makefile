quick:main.cpp ytp.cpp ssl_util.cpp
	g++ main.cpp ytp.cpp ssl_util.cpp -o client -lssl -lcrypto
#若沒有依賴文件，直接執行命令