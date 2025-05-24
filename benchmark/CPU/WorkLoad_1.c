/*
Consume CPU cycles by incrementing a variable in a loop.
*/

int main()
{
    unsigned int j = (unsigned int)100;  // Initialize j to 1
    unsigned int a = 0;                  // Initialize a to 0
    for (unsigned int i = 0; i < j; i++) // Loop from i = 0 to i < j (i.e., once)
    {
        a++; // Increment a by 1
    }
}
