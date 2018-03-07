
#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef long long ADDR;   /* 8 or 4 byte. (memdump) */

int memdump(ADDR *dmem, int byte);
int memdump64(ADDR *dmem, int byte);


#endif		/* _DEBUG_H_ */
