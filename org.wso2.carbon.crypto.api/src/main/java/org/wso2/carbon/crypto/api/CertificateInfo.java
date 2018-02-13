package org.wso2.carbon.crypto.api;

import java.security.cert.Certificate;

/**
 *
 * A simple data holder class which is used to encapsulate either the {@link Certificate} or
 * the certificate information which can be used to retrieve the certificate.
 *
 *<p>
 * {@link KeyResolver} implementations return {@link CertificateInfo} based on the given {@link CryptoContext},
 * and {@link ExternalCryptoProvider} implementations use it for certificate retrieval.
 *</p>
 */
public class CertificateInfo {

    private String certificateAlias;
    private Certificate certificate;

    public CertificateInfo(String certificateAlias, Certificate certificate) {

        this.certificateAlias = certificateAlias;
        this.certificate = certificate;
    }

    public String getCertificateAlias() {

        return certificateAlias;
    }

    public Certificate getCertificate() {

        return certificate;
    }

    @Override
    public String toString() {

        return "CertificateInfo{" +
                "certificateAlias='" + certificateAlias + '\'' +
                ", certificate=" + certificate +
                '}';
    }
}
