quick:main.cpp ytp.cpp ssl_util.cpp
	g++ main.cpp ytp.cpp ssl_util.cpp -o client -lssl -lcrypto
clean:
	-rm *.o client
.PHONY:clean
#若沒有依賴文件，直接執行命令