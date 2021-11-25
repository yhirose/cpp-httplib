#include <httplib.h>
#include "WSdefs.h"
#include <thread>

/**
 * NOT PRODUCTION READY!
 * Use this code at your own risk! It "works", but may behave in unexpected ways
 * if the server drops your connection without warning, you may need to terminate the program manually
 * e.g. with ctrl-C
 * TODO: handle unexpected disconnect
 * TODO: find another websocket testing service
*/

std::mutex stream_send_mutex;

void sendTask(httplib::Stream &strm, const WSSPec::BYTE0_FLAGS::OPCODES frame_type, const std::string& payload = std::string(), bool is_mask = true);

void receiveThread(httplib::Stream &strm);

int main(int argc, char const *argv[])
{
    httplib::CustomProtocolHandlers protc_handlers {
        {
            "websocket",
            [](httplib::Stream &strm) {
                std::cerr << "entered WebSocket handler" << std::endl;
                bool stop = false;
                auto terminal = [&strm, &stop]() {
                    for(std::string command = "test56"; command != "q"; std::cin >> command) {
                        if(command == "p")
                            sendTask(strm, WSSPec::BYTE0_FLAGS::PING, "pingu");
                        else
                            sendTask(strm, WSSPec::BYTE0_FLAGS::TEXT, command);
                    }
                    stop = true;
                    sendTask(strm, WSSPec::BYTE0_FLAGS::CLOSE);
                };
                auto heartbeat = [&strm, &stop]() {
                    while(!stop) {
                        sendTask(strm, WSSPec::BYTE0_FLAGS::PING, "HB");
                        std::cerr << "sending HB" << std::endl;
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                    }
                };
                std::thread receiver(receiveThread, std::ref(strm));
                std::thread sender(terminal);
                // std::thread hb(heartbeat);
                receiver.join();
                sender.join();
                // hb.join();
                return true;
            }
        }
    };
    httplib::Headers headers {
        { "Connection", "upgrade" },
        { "Upgrade", "websocket" },
        { "Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==" },
        { "Sec-WebSocket-Version", "13" },
        // { "Origin", "http://localhost:9090"}
        { "Origin", "https://www.piesocket.com"}
    };
    // httplib::Client c("localhost", 9090);
    httplib::Client c("demo.piesocket.com", 80);

    std::cerr << "type a message, then hit enter to send" << std::endl;
    std::cerr << "enter p to send ping and q to negotiate a disconnect" << std::endl;

    auto res = c.Get(
        // "/",
        "/v3/channel_1?api_key=oCdCMcMPQpbvNjUIzqtvF1d2X2okWpDQj4AwARJuAgtjhzKxVEjQU6IdCjwm&notify_self",
        headers,
        protc_handlers
    );
    if(res) {
        std::cerr << std::endl;
        std::cerr << res->status << std::endl;
        std::cerr << res->body << std::endl;
    }
    return 0;
}

void sendTask(httplib::Stream &strm, const WSSPec::BYTE0_FLAGS::OPCODES frame_type, const std::string& payload = std::string(), bool is_mask = true) {
    std::lock_guard<std::mutex> stream_send_lock(stream_send_mutex);
    uint64_t ext_payload_len = 0;
    WSSPec::PAYLOAD_LEN_MODE payload_len_mode = WSSPec::NORMAL;
    const uint8_t mask[] = {
        0x47, 0x65, 0x33, 0xF3
    };
    // send frame headers
    {
        using namespace WSSPec::BYTE0_FLAGS;
        uint8_t byte0 = FIN | frame_type;
        strm.write(reinterpret_cast<const char*>(&byte0), sizeof(byte0));
    }
    {
        using namespace WSSPec::BYTE1_FLAGS;
        uint8_t byte1 = is_mask ? IS_MASKED : 0x0;
        size_t real_payload_len = payload.length();
        if (real_payload_len <= 125) {
            byte1 |= real_payload_len & PAYLOAD_LEN;
        } else if (real_payload_len < std::numeric_limits<uint16_t>::max()) {
            byte1 |= WSSPec::EXT_16_BIT;
            ext_payload_len = real_payload_len;
            payload_len_mode = WSSPec::EXT_16_BIT;
        } else {
            byte1 |= WSSPec::EXT_64_BIT;
            ext_payload_len = real_payload_len;
            payload_len_mode = WSSPec::EXT_64_BIT;
        }
        strm.write(reinterpret_cast<const char*>(&byte1), sizeof(byte1));
    }
    switch(payload_len_mode) {
        using namespace WSSPec;
        case EXT_16_BIT:
            strm.write(reinterpret_cast<const char *>(&ext_payload_len), sizeof(uint16_t));
            break;
        case EXT_64_BIT:
            strm.write(reinterpret_cast<const char *>(&ext_payload_len), sizeof(uint64_t));
            break;
        case NORMAL:
        default:
            break;
    }
    if(is_mask)
        strm.write(reinterpret_cast<const char *>(&mask), sizeof(mask));
    for(size_t i = 0; i < payload.length(); i++) {
        uint8_t byte = payload.at(i);
        if(is_mask)
            byte ^= mask[i % 4];
        strm.write(reinterpret_cast<const char *>(&byte), sizeof(byte));
    }
}

void receiveThread(httplib::Stream &strm) {
    const size_t bufsize = 32;
    char buffer[bufsize];
    struct WSSPec::WSFRAME frame {};
    do {
        static bool waiting = false;
        static size_t read_count = 0;
        static size_t payload_len = 0;
        static size_t header_size = 2;
        ssize_t readsize;

        if(!strm.is_readable()) {
            std::this_thread::yield();
            if(!waiting) {
                waiting = true;
                std::cerr << "cannot read" << std::endl;
                // sendTask(strm, WSSPec::BYTE0_FLAGS::PING, "pingu");
            }
            continue;
        }
        waiting = false;
        {
            std::lock_guard<std::mutex> stream_send_lock(stream_send_mutex);
            readsize = strm.read(buffer, bufsize);
        }

        // function to check if a frame has been completed and process it
        auto get_frame = [&](){
            if (read_count > 1 && read_count - header_size >= payload_len) { // frame completely received
                read_count = 0;
                header_size = 2;
                payload_len = 0;
                switch(frame.opcode) {
                    using namespace WSSPec::BYTE0_FLAGS;
                    case PING:
                        std::cerr << "received ping with payload "
                            << frame.payload << ", will echo"
                            << std::endl;
                        sendTask(strm, PONG, frame.payload);
                        break;
                    case PONG:
                        std::cerr << "received pong with payload "
                            << frame.payload
                            << std::endl;
                        break;
                    case TEXT:
                        std::cout << frame.payload << std::endl;
                        break;
                }
                frame.payload.clear();
            }
        };

        for (size_t i = 0; i < readsize; i++, get_frame(), read_count++)
        {
            if(read_count == 0) {
                using namespace WSSPec::BYTE0_FLAGS;
                frame.FIN = buffer[i] & FIN;
                frame.RSV_FLAGS = buffer[i] & RSV;
                frame.opcode = buffer[i] & OPCODE;
            } else if (read_count == 1) {
                using namespace WSSPec::BYTE1_FLAGS;
                frame.masked = buffer[i] & IS_MASKED;
                frame.payload_len = buffer[i] & PAYLOAD_LEN;
                if (frame.masked)
                    header_size += sizeof(frame.masking_key);
                if (frame.payload_len == WSSPec::EXT_16_BIT)
                    header_size += sizeof(uint16_t);
                else if (frame.payload_len == WSSPec::EXT_64_BIT)
                    header_size += sizeof(uint64_t);
            } else {
                if (read_count < 4 && frame.payload_len == WSSPec::EXT_16_BIT) {
                    frame.payload_len_ext = 
                        read_count == 2
                        ? static_cast<uint8_t>(buffer[i])
                        : static_cast<uint8_t>(buffer[i]) + frame.payload_len_ext << 8;
                } else if (read_count < 10 && frame.payload_len == WSSPec::EXT_64_BIT) {
                    frame.payload_len_ext = 
                        read_count == 2
                        ? static_cast<uint8_t>(buffer[i])
                        : static_cast<uint8_t>(buffer[i]) + frame.payload_len_ext << 8;
                } else {
                    if (frame.payload_len != 0 && frame.payload.empty()) {
                        if (frame.payload_len < 126) {
                            payload_len = frame.payload_len;
                        } else {
                            payload_len = frame.payload_len_ext;
                        }
                        std::cerr << "interpreted length: "
                            << payload_len << std::endl;

                        frame.payload.reserve(payload_len);
                        std::cerr << "Received frame of type ";
                        switch(frame.opcode) {
                            using namespace WSSPec::BYTE0_FLAGS;
                            case PING:
                                std::cerr << "PING";
                                break;
                            case PONG:
                                std::cerr << "PONG";
                                break;
                            case TEXT:
                                std::cerr << "TEXT";
                                break;
                            case BINARY:
                                std::cerr << "BINARY";
                                break;
                            case CONTINUE:
                                std::cerr << "CONTINUE";
                                break;
                            case CLOSE:
                                std::cerr << "CLOSE";
                                break;
                        }
                        std::cerr << std::endl;
                    }

                    if(frame.masked) {
                        if (read_count < header_size) {
                            frame.masking_key = header_size - read_count == sizeof(frame.masking_key)
                                ? static_cast<uint8_t>(buffer[i])
                                : static_cast<uint8_t>(buffer[i]) + (frame.masking_key << 8);
                        } else {
                            uint8_t *mask = reinterpret_cast<uint8_t *>(&frame.masked);
                            buffer[i] = buffer[i] ^ mask[i % 4];
                        }
                    }
                    if (read_count >= header_size
                            && read_count - header_size < payload_len)
                        frame.payload.push_back(buffer[i]);
                }
            }
        }
        get_frame();
    } while (frame.opcode != WSSPec::BYTE0_FLAGS::CLOSE);
    std::cerr << "Quit" << std::endl;
}
