
#include "certificate.h"

namespace cpp { namespace utils {

    class CertificateStore
    {
    public:
        CertificateStore();
        ~CertificateStore();

        bool add_crl(X509_CRL* crl);
        bool add_trusted(const Certificate& cert);
        bool add_untrusted(const Certificate& cert);
        void clear_untrusted();

        bool verify_signatures(const Certificate& cert) const;
        bool verify_chain(const Certificate& cert) const;
        bool verify_ocsp(const Certificate& cert, const Certificate& issuer);
        bool verify(const Certificate& cert) const;

    private:
        X509_STORE* _store;
        STACK_OF(X509)* _untrusted;
    };

}}