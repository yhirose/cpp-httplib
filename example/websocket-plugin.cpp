#define CPPHTTPLIB_OPENSSL_SUPPORT
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
                    for(std::string command = "p"; command != "q"; std::cin >> command) {
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
        { "Accept", "*/*" },
        { "Connection", "upgrade" },
        { "Upgrade", "websocket" },
        { "Sec-Fetch-Dest", "websocket" },
        { "Sec-Fetch-Mode", "websocket" },
        { "Sec-Fetch-Site", "same-origin" },
        { "Sec-Websocket-Key", "dGhlIHNhbXBsZSBub25jZQ==" },
        { "Sec-WebSocket-Version", "13" },
        // { "Origin", "http://localhost:9090"}
        { "Origin", "https://websocketstest.com"}
        // { "Origin", "https://echo.websocket.events" }
    };
    // httplib::Client c("localhost", 9090);
    httplib::SSLClient c("websocketstest.com", 443);
    // httplib::Client c("echo.websocket.events", 80);
    std::cerr << "websocketstest.com accepts commands 'version,' 'echo,<message>' and 'timer,'" << std::endl;

    std::cerr << "type a message, then hit enter to send" << std::endl;
    std::cerr << "enter p to send ping and q to negotiate a disconnect" << std::endl;

    auto res = c.Get(
        // "/",
        "/service",
        headers,
        protc_handlers
    );
    if(res) {
        std::cerr << std::endl;
        std::cerr << res->status << std::endl;
        std::cerr << res->body << std::endl;
    } else {
        std::cerr << res.error() << std::endl;
    }
    return 0;
}

void sendTask(httplib::Stream &strm, const WSSPec::BYTE0_FLAGS::OPCODES frame_type, const std::string& payload, bool is_mask) {
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
        static enum WSSPec::STATE state = WSSPec::IDLE;
        static size_t length_bytes_read = 0;
        static size_t mask_bytes_read = 0;
        static size_t payload_bytes_read = 0;
        ssize_t readsize;

        if(!httplib::detail::is_socket_alive(strm.socket())) {
            std::cerr << "disconnected" << std::endl;
            break;
        }
        if(!strm.is_readable()) {
            std::this_thread::yield();
            if(!waiting) {
                waiting = true;
                std::cerr << "websocket idle" << std::endl;
                // sendTask(strm, WSSPec::BYTE0_FLAGS::PING, "pingu");
            }
            continue;
        }
        waiting = false;
        {
            std::lock_guard<std::mutex> stream_send_lock(stream_send_mutex);
            readsize = strm.read(buffer, bufsize);
        }

        for (size_t i = 0; i < readsize; i++)
        {
            switch (state)
            {
                using namespace WSSPec;
                case IDLE:
                    state = READ_BYTE_0;
                case READ_BYTE_0: {
                using namespace WSSPec::BYTE0_FLAGS;
                frame.FIN = buffer[i] & FIN;
                frame.RSV_FLAGS = buffer[i] & RSV;
                frame.opcode = buffer[i] & OPCODE;
                    state = READ_BYTE_1;
                    break;
                }
                case READ_BYTE_1: {
                using namespace WSSPec::BYTE1_FLAGS;
                frame.masked = buffer[i] & IS_MASKED;
                frame.payload_len = buffer[i] & PAYLOAD_LEN;
                    if (frame.payload_len == WSSPec::EXT_16_BIT) {
                        frame.payload_len = 0;
                        state = READ_U16_LEN;
                    }
                    else if (frame.payload_len == WSSPec::EXT_64_BIT) {
                        frame.payload_len = 0;
                        state = READ_U64_LEN;
                    }
                    else
                        state = frame.masked ? READ_MASK : READ_PAYLOAD;
                    break;
                }
                case READ_U16_LEN:
                    frame.payload_len = static_cast<uint8_t>(buffer[i]) + frame.payload_len << 8;
                    if (++length_bytes_read >= sizeof(uint16_t)) {
                        length_bytes_read = 0;
                        state = frame.masked ? READ_MASK : READ_PAYLOAD;
                    }
                    break;
                case READ_U64_LEN:
                    frame.payload_len = static_cast<uint8_t>(buffer[i]) + frame.payload_len << 8;
                    if (++length_bytes_read >= sizeof(uint64_t)) {
                        length_bytes_read = 0;
                        state = frame.masked ? READ_MASK : READ_PAYLOAD;
                    }
                    break;
                case READ_MASK:
                    if (mask_bytes_read == 0)
                        frame.masking_key = 0;
                    frame.masking_key = static_cast<uint8_t>(buffer[i]) + (frame.masking_key << 8);
                    if (++mask_bytes_read >= sizeof(frame.masking_key)) {
                        mask_bytes_read = 0;
                        state = READ_PAYLOAD;
                        }
                    break;
                case READ_PAYLOAD:
                    if (payload_bytes_read == 0) {
                        std::cerr << "interpreted length: "
                            << frame.payload_len << std::endl;

                        size_t capacity = frame.payload_len;
                        if (!frame.payload.empty())
                            capacity += frame.payload.capacity();
                        frame.payload.reserve(capacity);

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
                            default:
                                std::cerr << std::hex << (int) frame.opcode << std::dec;
                                break;
                        }
                        std::cerr << std::endl;
                    }

                    if (frame.masked) {
                            uint8_t *mask = reinterpret_cast<uint8_t *>(&frame.masked);
                            buffer[i] = buffer[i] ^ mask[i % 4];
                        }
                    frame.payload.push_back(buffer[i]);
                    
                    if (++payload_bytes_read >= frame.payload_len) {
                        payload_bytes_read = 0;
                        if (frame.FIN) {
                            state = PRINT_MESSAGE;
                        } else {
                            state = IDLE;
                            // break;
                    }
                    }
                    else break;
                case PRINT_MESSAGE:
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
                    state = IDLE;
                    break;
                default:
                    break;
            }
        }
    } while (frame.opcode != WSSPec::BYTE0_FLAGS::CLOSE);
    std::cerr << "Quit" << std::endl;
}
