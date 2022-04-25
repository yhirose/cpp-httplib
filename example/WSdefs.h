#include <stdint.h>
#include <string>

namespace WSSPec {
    struct WSFRAME {
        bool FIN;
        uint8_t RSV_FLAGS = 0;
        uint8_t opcode;
        bool masked;
        uint64_t payload_len;
        uint32_t masking_key = 0;
        std::string payload = "";
    };
    namespace BYTE0_FLAGS {
        enum MASKS : uint8_t {
            FIN = 0b10000000,
            RSV = 0b01110000,
            OPCODE = 0b00001111
        };
        enum OPCODES : uint8_t {
            CONTINUE = 0x00,
            TEXT = 0x01,
            BINARY = 0x02,
            CLOSE = 0x08,
            PING = 0x09,
            PONG = 0x0A
        };
    }
    namespace BYTE1_FLAGS {
        enum MASKS : uint8_t {
            IS_MASKED = 0b10000000,
            PAYLOAD_LEN = 0b01111111
        };
    }
    enum PAYLOAD_LEN_MODE : uint8_t {
        NORMAL = 0,
        EXT_16_BIT = 126,
        EXT_64_BIT = 127
    };
    enum STATE {
        IDLE,
        READ_BYTE_0,
        READ_BYTE_1,
        READ_U16_LEN,
        READ_U64_LEN,
        READ_MASK,
        READ_PAYLOAD,
        PRINT_MESSAGE
    };
}
