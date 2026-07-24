//
//  upload.cc
//
//  Copyright (c) 2026 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <fstream>
#include <httplib.h>
#include <iostream>

#ifdef _WIN32
#include <direct.h>
#define mkdir(dir, mode) _mkdir(dir)
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

using namespace httplib;
using namespace std;

const char *html = R"(
<form id="formElem">
  <input type="file" name="image_file" accept="image/*">
  <input type="file" name="text_file" accept="text/*">
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

  svr.Post("/post", [](const Request &req, Response &res) {
    const auto &image_file = req.form.get_file("image_file");
    const auto &text_file = req.form.get_file("text_file");

    cout << "image file length: " << image_file.content.length() << endl
         << "image file name: " << image_file.filename << endl
         << "text file length: " << text_file.content.length() << endl
         << "text file name: " << text_file.filename << endl;

    // Reduce a client-supplied filename to a safe base name, or return an
    // empty string if it cannot be trusted (empty, ".", "..", or contains a
    // path separator).
    auto sanitize = [](const string &filename) -> string {
      auto name = filesystem::path(filename).filename().string();
      if (name.empty() || name == "." || name == ".." ||
          name.find('/') != string::npos || name.find('\\') != string::npos ||
          name.find("..") != string::npos) {
        return string();
      }
      return name;
    };

    const auto image_name = sanitize(image_file.filename);
    const auto text_name = sanitize(text_file.filename);
    if (image_name.empty() || text_name.empty()) {
      res.status = StatusCode::BadRequest_400;
      return;
    }

    mkdir("uploads", 0755);
    {
      ofstream ofs(string("uploads/") + image_name, ios::binary);
      if (!ofs) {
        res.status = StatusCode::InternalServerError_500;
        res.set_content("Failed to write image file", "text/plain");
        return;
      }
      ofs << image_file.content;
    }
    {
      ofstream ofs(string("uploads/") + text_name);
      if (!ofs) {
        res.status = StatusCode::InternalServerError_500;
        res.set_content("Failed to write text file", "text/plain");
        return;
      }
      ofs << text_file.content;
    }

    res.set_content("done", "text/plain");
  });

  svr.listen("localhost", 1234);
}
