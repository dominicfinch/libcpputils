#pragma once

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <openssl/x509.h>

namespace iar { namespace utils {

    class ECC;
    class RSA;

    /**
     * @brief CertificateBuilder — wrapper around OpenSSL 3.x for creating,
     *        signing, exporting, and saving X.509 certificates.
     */
    class CertificateBuilder {
    public:
        CertificateBuilder();
        ~CertificateBuilder() = default;

        // --- Basic certificate setup
        void set_subject(const std::string& dn);
        void set_validity_days(int days);
        void set_serial_number(long serial);

        // --- Attach public key from your ECC or RSA key wrappers
        void set_public_key_from_ecc(ECC& ecc);
        void set_public_key_from_rsa(RSA& rsa);

        // --- Signing
        void self_sign_with_ecc(ECC& ecc);
        void self_sign_with_rsa(RSA& rsa);
        void sign_with_ca(const CertificateBuilder& ca, ECC& ecc);
        void sign_with_ca(const CertificateBuilder& ca, RSA& rsa);

        // --- Export / save
        bool save_pem(const std::string& path) const;
        bool save_der(const std::string& path) const;
        bool get_certificate_pem(std::string& out) const;
        bool get_certificate_der(std::vector<uint8_t>& out) const;
        bool export_to_pkcs12(const std::string& path, const std::string& password, RSA& rsa) const;

        // --- Access raw X509 for advanced operations
        X509* x509() const { return x509_.get(); }

    private:
        std::unique_ptr<X509, decltype(&X509_free)> x509_;
        void sign_with_private_pem(const std::string& pem, const EVP_MD* md);
    };

    /**
     * @brief Certificate — helper to load, inspect, and verify certificates.
     */
    class Certificate {
    public:
        Certificate();
        ~Certificate() = default;

        bool load_from_pem(const std::string& pem);
        bool load_from_pem_file(const std::string& path);
        bool load_from_der_file(const std::string& path);

        bool get_common_name(std::string& cn) const;
        bool verify_signature(const Certificate& issuer) const;

    private:
        std::unique_ptr<X509, decltype(&X509_free)> x509_;
    };


}}