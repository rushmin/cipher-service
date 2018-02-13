package org.wso2.carbon.crypto.api;

import java.security.PrivateKey;

/**
 * The service contract of an implementation of a private key retriever.
 * <p>
 * <b>Important:</b> Using this interface is discouraged. It was introduced to deal with situations where
 * third party libraries (e.g. opensaml) expects a private for crypto operations rather than letting another component
 * to do the operation for them.
 * </p>
 * <p>
 * If the need of a private key can be avoided, <b>do NOT</b> use this interface. Use {@link CryptoService} instead.
 * </p>
 */
public interface PrivateKeyRetriever {

    PrivateKey getPrivateKey(CryptoContext cryptoContext) throws CryptoException;

}
