
#include "certificate_store.h"
#include <openssl/ocsp.h>

namespace cpp { namespace utils {

    CertificateStore::CertificateStore()
    {
        _store = X509_STORE_new();
        _untrusted = sk_X509_new_null();

        X509_STORE_set_flags(_store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

        // Optional: load system trust store
        X509_STORE_set_default_paths(_store);
    }

    CertificateStore::~CertificateStore()
    {
        if (_store) X509_STORE_free(_store);
        if (_untrusted) sk_X509_free(_untrusted);
    }

    bool CertificateStore::add_crl(X509_CRL* crl)
    {
        if (!_store || !crl) return false;
        return X509_STORE_add_crl(_store, crl) == 1;
    }

    bool CertificateStore::add_trusted(const Certificate& cert)
    {
        if (!_store || !cert.raw()) return false;
        return X509_STORE_add_cert(_store, cert.raw()) == 1;
    }

    bool CertificateStore::add_untrusted(const Certificate& cert)
    {
        if (!_untrusted || !cert.raw()) return false;
        auto success = sk_X509_push(_untrusted, cert.raw()) != 0;
        if(success) X509_up_ref(cert.raw());
        return success;
    }

    void CertificateStore::clear_untrusted()
    {
        if (_untrusted)
            sk_X509_free(_untrusted);
        _untrusted = sk_X509_new_null();
    }
    
    bool CertificateStore::verify_signatures(const Certificate& cert) const
    {
        if (!cert.raw()) return false;

        X509* current = cert.raw();

        // Try to verify against untrusted chain first, then trusted store
        for (int i = 0; i < sk_X509_num(_untrusted); ++i)
        {
            X509* issuer = sk_X509_value(_untrusted, i);
            EVP_PKEY* pubkey = X509_get_pubkey(issuer);
            if (!pubkey) continue;

            int ret = X509_verify(current, pubkey);
            EVP_PKEY_free(pubkey);

            if (ret == 1)
                return true;
        }

        // Try trusted store certs
        // (OpenSSL doesn't expose direct iteration easily, so fallback to chain verify)
        return verify_chain(cert);
    }

    bool CertificateStore::verify_chain(const Certificate& cert) const
    {
        if (!_store || !cert.raw()) return false;

        X509_STORE_CTX* ctx = X509_STORE_CTX_new();
        if (!ctx) return false;

        if (X509_STORE_CTX_init(ctx, _store, cert.raw(), _untrusted) != 1)
        {
            X509_STORE_CTX_free(ctx);
            return false;
        }

        int ret = X509_verify_cert(ctx);
        X509_STORE_CTX_free(ctx);
        return ret == 1;
    }

    bool CertificateStore::verify_ocsp(const Certificate& cert, const Certificate& issuer)
    {
        std::string url = cert.get_ocsp_url();
        if (url.empty()) return false;

        OCSP_CERTID* id = OCSP_cert_to_id(nullptr, cert.raw(), issuer.raw());
        OCSP_REQUEST* req = OCSP_REQUEST_new();
        OCSP_request_add0_id(req, id);

        // You must send HTTP POST to OCSP server
        // OpenSSL provides OCSP_sendreq_bio()

        // Simplified (no full error handling):
        BIO* cbio = BIO_new_connect("ocsp.server:80"); // parse from URL
        if (!cbio) return false;

        if (BIO_do_connect(cbio) <= 0) return false;

        OCSP_RESPONSE* resp = OCSP_sendreq_bio(cbio, "/path", req);

        if (!resp) return false;

        int status = OCSP_response_status(resp);
        if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
            return false;

        OCSP_BASICRESP* basic = OCSP_response_get1_basic(resp);

        int reason;
        ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

        int cert_status = OCSP_resp_find_status(basic, id, &status, &reason, &rev, &thisupd, &nextupd);
        bool good = (cert_status == V_OCSP_CERTSTATUS_GOOD) && (status == OCSP_RESPONSE_STATUS_SUCCESSFUL);

        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(resp);
        BIO_free_all(cbio);

        return good;
    }

    bool CertificateStore::verify(const Certificate& cert) const
    {
        return verify_signatures(cert) && verify_chain(cert);
    }

}}