//
//  upload.cc
//
//  Copyright (c) 2019 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <httplib.h>
#include <iostream>
#include <fstream>
using namespace httplib;
using namespace std;

const char* html = R"(
<form id="formElem">
  <input type="file" name="file" accept="image/*">
  <input type="submit">
</form>
<script>
  formElem.onsubmit = async (e) => {
    e.preventDefault();
    let res = await fetch('/post', {
      method: 'POST',
      body: new FormData(formElem)
    });
    console.log(await res.text());
  };
</script>
)";

int main(void) {
  Server svr;

  svr.Get("/", [](const Request & /*req*/, Response &res) {
    res.set_content(html, "text/html");
  });

  svr.Post("/post", [](const Request & req, Response &res) {
    auto file = req.get_file_value("file");
    cout << "file length: " << file.content.length() << ":" << file.filename << endl;

    ofstream ofs(file.filename, ios::binary);
    ofs << file.content;

    res.set_content("done", "text/plain");
  });

  svr.listen("localhost", 1234);
}
