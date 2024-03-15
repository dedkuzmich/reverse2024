#include <windows.h>
#include <iostream>

using namespace std;

int main(int argc, char* argv[])
{
    MessageBoxA(0, "Kitty", "Hello", 0);
    cout << "Hello, Kitty!" << endl;
    system("pause");
    return EXIT_SUCCESS;
}
