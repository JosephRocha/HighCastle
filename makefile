all: HighCastle.c
	gcc -g -Wall -o HighCastle HighCastle.c -lpcap -ldnet

  clean: 
	$(RM) HighCastle
