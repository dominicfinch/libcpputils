#pragma once

#include <string>
#include "runner.h"

#include "tests/aes_tests.h"
#include "tests/bchain_tests.h"
#include "tests/btree_tests.h"
#include "tests/b58_tests.h"
#include "tests/b64_tests.h"
#include "tests/des3_tests.h"

#ifndef EXCLUDE_DH_TESTS
#include "tests/dh_tests.h"
#endif

#include "tests/certificate_tests.h"
#include "tests/ecc_tests.h"
#include "tests/hash_tests.h"
#include "tests/hex_tests.h"
#include "tests/llist_tests.h"
#include "tests/rsa_tests.h"
#include "tests/sc_contact_tests.h"
#include "tests/sc_transceiver_tests.h"
#include "tests/uuid_tests.h"
#include "tests/wallet_tests.h"

