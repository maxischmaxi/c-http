#include "test.h"

static int add(int a, int b)
{
    return a + b;
}

int main(void)
{
    CHECK(add(1, 2) == 3);
    CHECK(add(-1, 1) == 0);
    return test_report();
}
