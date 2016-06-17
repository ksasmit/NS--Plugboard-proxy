default:
	gcc -o pbproxy pbproxy.c -lcrypto -lpthread
run_client:
	./pbproxy -k 12345 localhost 5001
run_server:
	./pbproxy -l 5001 -k 12345 localhost 5002
run_nc:
	nc -l -p 5002
