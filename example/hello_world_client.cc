#include <iostream>
#include "httplib.h"

// Cliente HTTP minimalista usando cpp-httplib
// Llama a /hi en el servidor local y muestra la respuesta

int main() {
    httplib::Client cli("http://localhost:8080");

    if (auto res = cli.Get("/hi")) {
        if (res->status == 200) {
            std::cout << "Response: " << res->body << std::endl;
        } else {
            std::cout << "Server returned status " << res->status << std::endl;
        }
    } else {
        std::cout << "HTTP error: " << httplib::to_string(res.error()) << std::endl;
    }

    return 0;
}
