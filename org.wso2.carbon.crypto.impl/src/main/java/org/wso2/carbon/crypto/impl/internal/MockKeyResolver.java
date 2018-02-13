package org.wso2.carbon.crypto.impl.internal;

import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.KeyResolver;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;

public class MockKeyResolver extends KeyResolver{

    @Override
    public boolean isApplicable(CryptoContext cryptoContext) {

        return false;
    }

    @Override
    public PrivateKeyInfo getPrivateKeyInfo(CryptoContext cryptoContext) {

        return null;
    }

    @Override
    public CertificateInfo getCertificateInfo(CryptoContext cryptoContext) {

        return null;
    }
}
