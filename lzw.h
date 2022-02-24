#include <iostream>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include "murmur.h"


#define CODE_LENGTH 13

void string_copy(unsigned char* op, unsigned char * ip, int len);

void encoding(unsigned char*ip, int len, unsigned char *op, int &how_much_written);
