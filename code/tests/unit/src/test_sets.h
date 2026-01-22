#pragma once

#include <string>
#include "runner.h"

#ifndef EXCLUDE_BCHAIN_TESTS
#include "tests/bchain_tests.h"
#endif

#include "tests/btree_tests.h"
#include "tests/b58_tests.h"
#include "tests/b64_tests.h"
#include "tests/des3_tests.h"

#ifndef EXCLUDE_DH_TESTS
#include "tests/dh_tests.h"
#endif

#include "tests/certificate_builder_tests.h"
#include "tests/certificate_tests.h"
#include "tests/graph_search_tests.h"
#include "tests/p12_repository_tests.h"
#include "tests/pkcs12_manager_tests.h"
#include "tests/private_key_tests.h"
#include "tests/trust_store_tests.h"

#include "tests/aes_tests.h"
#include "tests/chacha_tests.h"
#include "tests/ecc_tests.h"
#include "tests/ed25519_tests.h"
#include "tests/hash_tests.h"
#include "tests/hex_tests.h"
#include "tests/llist_tests.h"
#include "tests/rsa_tests.h"
#include "tests/sc_contact_tests.h"
#include "tests/uuid_tests.h"
#include "tests/wallet_tests.h"

