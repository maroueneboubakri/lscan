#include<stdio.h>
#include<math.h>

int main()
{

printf("lscan binary test file statically linked with libm-2.13\n");

double result, x = 4.34;
  result = exp(x);
  printf("'e' raised to the power of %.2lf (e^%.2lf) = %.2lf\n", x, x, result);

return 0;
}
