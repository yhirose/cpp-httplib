//
//  httplib.h
//
//  Copyright (c) 2025 Yuji Hirose. All rights reserved.
//  MIT License
//

module;

#include "../httplib.h"

export module httplib;

export namespace httplib {
    using httplib::SSLVerifierResponse;
    using httplib::StatusCode;
    using httplib::Headers;
    using httplib::Params;
    using httplib::Match;
    using httplib::DownloadProgress;
    using httplib::UploadProgress;
    using httplib::Response;
    using httplib::ResponseHandler;
    using httplib::FormData;
    using httplib::FormField;
    using httplib::FormFields;
    using httplib::FormFiles;
    using httplib::MultipartFormData;
    using httplib::UploadFormData;
    using httplib::UploadFormDataItems;
    using httplib::DataSink;
    using httplib::ContentProvider;
    using httplib::ContentProviderWithoutLength;
    using httplib::ContentProviderResourceReleaser;
    using httplib::FormDataProvider;
    using httplib::FormDataProviderItems;
    using httplib::ContentReceiverWithProgress;
    using httplib::ContentReceiver;
    using httplib::FormDataHeader;
    using httplib::ContentReader;
    using httplib::Range;
    using httplib::Ranges;
    using httplib::Request;
    using httplib::Response;
    using httplib::Error;
    using httplib::to_string;
    using httplib::operator<<;
    using httplib::Stream;
    using httplib::TaskQueue;
    using httplib::ThreadPool;
    using httplib::Logger;
    using httplib::ErrorLogger;
    using httplib::SocketOptions;
    using httplib::default_socket_options;
    using httplib::status_message;
    using httplib::get_bearer_token_auth;
    using httplib::Server;
    using httplib::Result;
    using httplib::ClientConnection;
    using httplib::ClientImpl;
    using httplib::Client;

    #ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    using httplib::SSLServer;
    using httplib::SSLClient;
    #endif

    using httplib::hosted_at;
    using httplib::encode_uri_component;
    using httplib::encode_uri;
    using httplib::decode_uri_component;
    using httplib::decode_uri;
    using httplib::encode_path_component;
    using httplib::decode_path_component;
    using httplib::encode_query_component;
    using httplib::decode_query_component;
    using httplib::append_query_params;
    using httplib::make_range_header;
    using httplib::make_basic_authentication_header;

    using httplib::get_client_ip;

    namespace stream {
        using httplib::stream::Result;
        using httplib::stream::Get;
        using httplib::stream::Post;
        using httplib::stream::Put;
        using httplib::stream::Patch;
        using httplib::stream::Delete;
        using httplib::stream::Head;
        using httplib::stream::Options;
    }
}
