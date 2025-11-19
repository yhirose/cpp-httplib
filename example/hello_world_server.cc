#include <iostream>
#include "httplib.h"

// Servidor HTTP minimalista usando cpp-httplib
// Responde "Hello World!" en /hi

int main() {
    httplib::Server svr;

    svr.Get("/hi", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("Hello World!", "text/plain");
    });

    std::cout << "Server running on http://localhost:8080/hi" << std::endl;
    svr.listen("0.0.0.0", 8080);

    return 0;
}
