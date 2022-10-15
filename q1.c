#include "helpers.h"

int main () {
   
    printf("Testing xtime question 1\n");
	// Test with P = X^2
	uint8_t m = xtime(4);
	printf("Expected result : 0x8 ----> Result : 0x%x\n", m);

	// Test with P = X^7 + X^4 + X^2 + X + 1
	m = xtime(0x96);
	printf("Expected result : 0x37 ----> Result : 0x%x\n", m);
	printf("\n");
    return 0;
}