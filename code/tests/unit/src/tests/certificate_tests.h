
#pragma once

#include <string>
#include <vector>

// CertificateBuilder tests
bool test_certificatebuilder_set_subject();
bool test_certificatebuilder_set_validity_days();
bool test_certificatebuilder_set_serial_number();
bool test_certificatebuilder_set_public_key_from_rsa();
bool test_certificatebuilder_set_public_key_from_ecc();
bool test_certificatebuilder_self_sign_with_rsa();
bool test_certificatebuilder_self_sign_with_ecc();
bool test_certificatebuilder_sign_with_ca_rsa();
bool test_certificatebuilder_sign_with_ca_ecc();
bool test_certificatebuilder_save_pem();
bool test_certificatebuilder_save_der();
bool test_certificatebuilder_get_certificate_pem();
bool test_certificatebuilder_get_certificate_der();
bool test_certificatebuilder_export_to_pkcs12();

// Certificate tests
bool test_load_from_pem();
bool test_load_from_pem_file();
bool test_load_from_der_file();
bool test_get_common_name();
bool test_verify_signature_self_signed();