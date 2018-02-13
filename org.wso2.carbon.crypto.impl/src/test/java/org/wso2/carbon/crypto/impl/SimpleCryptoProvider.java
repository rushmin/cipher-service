package org.wso2.carbon.crypto.impl;

import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;

/**
 * A mock implementation of {@link InternalCryptoProvider} to be used for test cases.
 */
public class SimpleCryptoProvider implements InternalCryptoProvider {

    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        return new byte[0];
    }
}
