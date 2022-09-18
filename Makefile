

all: ufsend ufrec

ufsend: ufsend.c pbkdf2_extract.c
	cc ufsend.c pbkdf2_extract.c -o ufsend -lcrypto

ufrec: ufrec.c
	cc ufrec.c -o ufrec -lcrypto

clean:
	rm ufsend ufrec