#include <thread>
#include <iostream>
using namespace std;
int main(void) {
  cout << std::thread::hardware_concurrency() << endl;
}
