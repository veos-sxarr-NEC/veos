/*
 * debug common routines
 */

/*  for little endian  */


#include "debugtool.h"

/*
 *   memory dump (32bit)
 */
int memdump(ADDR *dmem, int byte)
{
	ADDR addr_start, addr_last;
	int *addrp;
	int i, j, loop;
	char  *p_1b;
	int  *p_4b;
	int same_flag, same_flag_bk;  /* 1=same as previous line, 0=different */

	/*  1 line = 16byte  */

	addr_start = (ADDR) dmem;
	addr_last = addr_start + byte;

	printf ("\n[dump] %p -  %p (%d (0x%x) Byte)\n",
		(char *)dmem, (char *)addr_last, byte, byte);

	loop = (byte + 15)>>4;
	addrp = (int *)addr_start;
	same_flag = 0;
	same_flag_bk = 0;
	for (j = 0; j < loop; j++) {
		/* mem check */
		p_4b = addrp;
		same_flag = 1;
		for (i = 0; i < 4; i++) {
			/* compare current 16byte with next 16byte */
			if (*(p_4b+i) != *(p_4b+4+i))
				same_flag = 0;
		}
		if ((same_flag == 0) && (same_flag_bk == 1)) {
			/* (previous == current != next) */
			printf ("*\n");
			addrp = addrp+4;
			same_flag_bk = same_flag;
			continue;
		}
		if ((same_flag == 1) &&  !(same_flag_bk == 0)) {
			/* (previous == current == next) */
			addrp = addrp+4;
			same_flag_bk = same_flag;
			continue;
		}
		same_flag_bk = same_flag;

		/* (previous != current) */
		/* mem dump */
		printf ("%016llx: ", (long long)addrp);

		p_4b = addrp;
		for (i = 0; i < 4; i++) {
			p_1b = (char *)p_4b;
			printf("%02x", *(p_1b+3)&0xff);
			printf("%02x", *(p_1b+2)&0xff);
			printf("%02x", *(p_1b+1)&0xff);
			printf("%02x ", *p_1b&0xff);
			p_4b++;
		}
		printf("  ");

		/* text dump */
		p_1b = (char *) addrp;
		for (i = 0; i < 16; i++) {
			if ((*p_1b >= 0x20) && (*p_1b <= 0x7e))
				printf("%c", *p_1b);
			else
				printf(" ");

			p_1b++;
		}
		printf("\n");

		addrp = addrp+4;
	}
	if (same_flag == 1)
		printf ("*\n\n");

	return 0;
}

/*
 *   memory dump
 */
int memdump64(ADDR *dmem, int byte)
{
	ADDR addr_start, addr_last;
	int *addrp;
	int i, j, loop;
	char  *p_1b;
	int  *p_4b;
	long long *p_8b;
	int same_flag, same_flag_bk;  /* 1=same as previous line, 0=different */

	/*  1 line = 16byte  */

	addr_start = (ADDR) dmem;
	addr_last = addr_start + byte;

	printf ("\n[dump] %p -  %p (%d (0x%x) Byte)\n",
		(char *)dmem, (char *)addr_last, byte, byte);

	loop = (byte + 15) >> 4;
	addrp = (int *)addr_start;
	same_flag = 0;
	same_flag_bk = 0;
	for (j = 0; j < loop; j++) {
		/* mem check */
		p_4b = addrp;
		same_flag = 1;
		for (i = 0; i < 4; i++) {
			/* compare current 16byte with next 16byte */
			if (*(p_4b+i) != *(p_4b+4+i))
				same_flag = 0;
		}
		if ((same_flag == 0) && (same_flag_bk == 1)) {
			/* (previous == current != next) */
			printf ("*\n");
			addrp = addrp+4;
			same_flag_bk = same_flag;
			continue;
		}
		if ((same_flag == 1) &&  !(same_flag_bk == 0)) {
			/* (previous == current == next) */
			addrp = addrp+4;
			same_flag_bk = same_flag;
			continue;
		}
		same_flag_bk = same_flag;

		/* (previous != current) */
		/* mem dump */
		printf ("%016llx: ", (long long)addrp);

		p_8b = (long long *)addrp;
		for (i = 0; i < 2; i++) {
			p_1b = (char *)p_8b;
			printf("%02x", *(p_1b+7)&0xff);
			printf("%02x", *(p_1b+6)&0xff);
			printf("%02x", *(p_1b+5)&0xff);
			printf("%02x ", *(p_1b+4)&0xff);

			printf("%02x", *(p_1b+3)&0xff);
			printf("%02x", *(p_1b+2)&0xff);
			printf("%02x", *(p_1b+1)&0xff);
			printf("%02x ", *p_1b&0xff);
			p_8b++;
		}
		printf("  ");

		/* text dump */
		p_1b = (char *) addrp;
		for (i = 0; i < 1 ; i++) {
			if ((*p_1b >= 0x20) && (*p_1b <= 0x7e))
				printf("%c", *p_1b);
			else
				printf(" ");
			p_1b++;
		}
		printf("\n");

		addrp = addrp+4;
	}
	if (same_flag == 1) {
		printf ("*\n\n");
	}

	return 0;
}
