#include <stdio.h>
#include <unistd.h>

int main(int argc, char const *argv[])
{

    while(1){
        
        sleep(10);

        for(int i = 0; i < 1000; i++)
            putchar(getchar());
    }
    return 0;
}
