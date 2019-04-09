all: ap client adversary

ap: AP.c
	gcc -o ap AP.c -lcrypto
client: client.c
	gcc -o client client.c -lcrypto -lpthread
adversary: Adversary.c
	gcc -o adversary Adversary.c -lpthread
