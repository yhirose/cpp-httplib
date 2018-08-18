// FreeBookBackEnd.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "httplib.h"

#define SERVER_CERT_FILE "./Auth/cert.pem"
#define SERVER_PRIVATE_KEY_FILE "./Auth/key.pem"

int main()
{
	//httplib::SSLServer server(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
	httplib::Server server;

	if (!server.is_valid()) {
		system("pause");
		return -1;
	}

	server.Get("/home", [](const httplib::Request& req, httplib::Response& res) {
		res.set_content("lol", "text/plain");
	});

	server.Post("/login", [](const httplib::Request& req, httplib::Response& res) {

	});

	server.Post("/createaccount", [](const httplib::Request& req, httplib::Response& res) {

	});

	server.listen("localhost", 1234);

	return 0;
}