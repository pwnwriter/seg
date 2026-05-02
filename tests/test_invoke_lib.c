/* test shared library for seg invoke */

int add(int a, int b) { return a + b; }

int multiply(int a, int b) { return a * b; }

double divide(double a, double b) { return a / b; }

const char *greet(void) { return "hello from seg!"; }

int negate(int x) { return -x; }
