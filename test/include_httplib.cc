// The sole purpose of this file is to include httplib.h in a separate
// compilation unit, thus verifying that inline keywords have not been forgotten
// when linked together with test.cc.

#include <httplib.h>

// The library no longer calls these, but subclasses that override
// process_and_close_socket() do. Instantiating them here, where the split build
// does not reach, keeps a change to process_server_socket_core() from breaking
// them unnoticed.
struct IncludeHttplibServeNothing {
  bool operator()(httplib::Stream &, bool, bool &) const { return false; }
};
auto include_httplib_process_server_socket =
    &httplib::detail::process_server_socket<IncludeHttplibServeNothing>;
#ifdef CPPHTTPLIB_SSL_ENABLED
auto include_httplib_process_server_socket_ssl =
    &httplib::detail::process_server_socket_ssl<IncludeHttplibServeNothing>;
#endif
