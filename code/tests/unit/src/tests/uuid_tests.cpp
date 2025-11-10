#include "uuid_tests.h"
#include "uuid.h"

bool test_uuid_generate()
{
    int8_t expectedSize = (2*16) + 4;       // 16 bytes in uuid_t format --> Convert to hex (*2) -> add '-' chars (+4) => Result: 36 e.g. c1a58a0b-9a15-45ac-9d20-a5b685712c4a
    std::string id = iar::utils::generate_uuid();
    return !id.empty() && id.size() == expectedSize;
}