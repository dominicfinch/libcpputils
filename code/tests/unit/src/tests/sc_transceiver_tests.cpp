
#include "sc/transceiver.h"
#include "sc_transceiver_tests.h"
#include <iostream>

bool test_open_channel() {
    iar::utils::SCTransceiver user1, user2;

    user1.RandomInitialize();
    user2.RandomInitialize();

    auto user2_uid_str = user2.selfContact()->uid();
    auto handshakeReq1 = user1.OpenChannel(user2_uid_str, user2.selfContact());

    auto user1_uid_str = user1.selfContact()->uid();
    auto handshakeReq2 = user2.OpenChannel(user1_uid_str, user1.selfContact());

    return handshakeReq1 && handshakeReq2;
}

bool test_close_channel()
{
    iar::utils::SCTransceiver user1, user2;

    user1.RandomInitialize();
    user2.RandomInitialize();

    auto user2_uid_str = user2.selfContact()->uid();
    //std::cout << "user2_uid_str: " << user2_uid_str << "\n";
    auto handshakeReq1 = user1.OpenChannel(user2_uid_str, user2.selfContact());

    auto user1_uid_str = user1.selfContact()->uid();
    //std::cout << "user1_uid_str: " << user1_uid_str << "\n";
    auto handshakeReq2 = user2.OpenChannel(user1_uid_str, user1.selfContact());

    if(!handshakeReq1 | !handshakeReq2) return false;

    auto cc1 = user1.CloseChannel(user2_uid_str);
    auto cc2 = user2.CloseChannel(user1_uid_str);
    return cc1 && cc2;
}

bool test_export_contact()
{
    return false;
}

bool test_import_contact()
{
    return false;
}

bool test_open_channel_send_receive()
{
    iar::utils::SCTransceiver user1, user2;

    user1.RandomInitialize();
    user2.RandomInitialize();

    auto user2_uid_str = user2.selfContact()->uid();
    //std::cout << "user2_uid_str: " << user2_uid_str << "\n";
    auto handshakeReq1 = user1.OpenChannel(user2_uid_str, user2.selfContact());

    auto user1_uid_str = user1.selfContact()->uid();
    //std::cout << "user1_uid_str: " << user1_uid_str << "\n";
    auto handshakeReq2 = user2.OpenChannel(user1_uid_str, user1.selfContact());

    if(!handshakeReq1 | !handshakeReq2) return false;

    // Test binary roundtrip
    std::vector<uint8_t> test_input = {'H', 'e', 'l', 'l', 'o', 0, 1, 2, 3, '\0'};
    std::vector<uint8_t> test_output, roundtrip_output;

    auto encryptEncodeResult = user1.EncryptEncodeContent(user2_uid_str, test_input, test_output);
    auto decryptDecodeResult = user2.DecryptDecodeContent(user1_uid_str, test_output, roundtrip_output);

    if(!encryptEncodeResult | !decryptDecodeResult) return false;
    if(test_input != roundtrip_output) return false;

    // Test strings roundtrips
    std::string test_input2 = "Hello World!";
    std::string test_output2, roundtrip_output2;

    auto encryptEncodeResult2 = user1.EncryptEncodeContent(user2_uid_str, test_input2, test_output2);
    //std::cout << "test_output2: " << test_output2 << "\n";

    auto decryptDecodeResult2 = user2.DecryptDecodeContent(user1_uid_str, test_output2, roundtrip_output2);
    //std::cout << "roundtrip_output2: " << roundtrip_output2 << "\n";

    if(!encryptEncodeResult2 | !decryptDecodeResult2) return false;
    return test_input2 == roundtrip_output2;
}

bool test_open_channel_send_receive_long_message()
{
    iar::utils::SCTransceiver user1, user2;

    user1.RandomInitialize();
    user2.RandomInitialize();

    auto user2_uid_str = user2.selfContact()->uid();
    //std::cout << "user2_uid_str: " << user2_uid_str << "\n";
    auto handshakeReq1 = user1.OpenChannel(user2_uid_str, user2.selfContact());

    auto user1_uid_str = user1.selfContact()->uid();
    //std::cout << "user1_uid_str: " << user1_uid_str << "\n";
    auto handshakeReq2 = user2.OpenChannel(user1_uid_str, user1.selfContact());

    if(!handshakeReq1 | !handshakeReq2) return false;

    // Test strings roundtrip
    std::string test_input2 = "Her father loved me, oft invited me; Still questioned \
    me the story of my life From year to year — the battles, sieges, fortunes That I \
    have passed. I ran it through, even from my boyish days To th’ very moment that he \
    bade me tell it. Wherein I spoke of most diastrous chances, Of moving accidents by \
    flood and field; Of hairbreadth scapes i’ the’ imminent deadly breach; Of being taken \
    by the insolent foe And sold to slavery; of my redemption thence And portance in my \
    travels’ history; Wherein of anters vast and deserts idle, Rough quarries, rocks, and \
    hills whose heads touch heaven, It was my hint to speak — such was the process; And of \
    the Cannibals that each other eat, The Anthropophagi, and men whose heads Do grow beneath \
    their shoulders. This to hear Would Desdemona seriously incline; But still the house \
    affairs would draw her thence; Which ever she could with haste dispatch, She’ld come \
    again, and with a greedy ear Devour up my discourse. Which I observing, Took once a \
    pliant hour, and found good means To draw from her a prayer of earnest heart That I \
    would all my pilgrimage dilate, Whereof by parcels she had something heard, But not \
    intentively. I did consent, And often did beguile her of her tears When I did speak \
    of some distressful stroke That my youth suffered. My story being done, She gave me \
    for my pains a world of sighs. She swore, i’ faith, ’twas strange, ’twas passing strange; \
    ‘Twas pitiful, ’twas wondrous pitiful. She wished she had not heard it; yet she wished \
    That heaven had made her such a man. She thanked me; And bade me, if I had a friend that \
    loved her, I should but teach him how to tell my story, And that would woo her. Upon this \
    hint I spake. She loved me for the dangers I had passed, And I loved her that she did pity \
    them. This only is the witchcraft I have used.";
    std::string test_output2, roundtrip_output2;

    auto encryptEncodeResult2 = user1.EncryptEncodeContent(user2_uid_str, test_input2, test_output2);
    //std::cout << "test_output2: " << test_output2 << "\n";

    auto decryptDecodeResult2 = user2.DecryptDecodeContent(user1_uid_str, test_output2, roundtrip_output2);
    //std::cout << "roundtrip_output2: " << roundtrip_output2 << "\n";

    if(!encryptEncodeResult2 | !decryptDecodeResult2) return false;
    return test_input2 == roundtrip_output2;
}