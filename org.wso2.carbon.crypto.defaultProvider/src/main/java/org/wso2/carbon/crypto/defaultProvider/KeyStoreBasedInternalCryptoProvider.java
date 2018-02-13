package org.wso2.carbon.crypto.defaultProvider;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * The Java Keystore based implementation of {@link InternalCryptoProvider}
 */
public class KeyStoreBasedInternalCryptoProvider implements InternalCryptoProvider {

    private static Log log = LogFactory.getLog(KeyStoreBasedInternalCryptoProvider.class);

    private KeyStore keyStore;
    private String keyAlias;
    private String keyPassword;

    public KeyStoreBasedInternalCryptoProvider(KeyStore keyStore, String keyAlias, String keyPassword) {

        this.keyStore = keyStore;
        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword;
    }

    /**
     * Computes and returns the ciphertext of the given cleartext, using the underlying key store.
     *
     * @param cleartext               The cleartext to be encrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider
     * @return the ciphertext
     * @throws CryptoException
     */
    @Override
    public byte[] encrypt(byte[] cleartext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        try {
            Cipher cipher;

            if (StringUtils.isBlank(javaSecurityAPIProvider)) {
                cipher = Cipher.getInstance(algorithm);
            } else {
                cipher = Cipher.getInstance(algorithm, javaSecurityAPIProvider);
            }

            Certificate certificate = getCertificateFromStore();

            if (log.isDebugEnabled()) {
                log.debug("Certificate used for encrypting : " + certificate);
            }

            cipher.init(Cipher.ENCRYPT_MODE, certificate.getPublicKey());

            byte[] ciphertext = cipher.doFinal(cleartext);

            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully encrypted data using the algorithm '%s' and the " +
                        "Java Security API provider '%s'", algorithm, javaSecurityAPIProvider));
            }

            return ciphertext;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException
                | IllegalBlockSizeException | KeyStoreException | InvalidKeyException | NoSuchProviderException e) {
            String errorMessage = String.format("An error occurred while encrypting using the algorithm : '%s'"
                    , algorithm);
            log.error(errorMessage);
            throw new CryptoException(errorMessage, e);
        }
    }

    /**
     * Computes and returns the cleartext of the given ciphertext.
     *
     * @param ciphertext              The ciphertext to be decrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the decryption operation.
     */
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider) throws CryptoException {

        try {
            Cipher cipher;

            if (StringUtils.isBlank(javaSecurityAPIProvider)) {
                cipher = Cipher.getInstance(algorithm);
            } else {
                cipher = Cipher.getInstance(algorithm, javaSecurityAPIProvider);
            }

            cipher.init(Cipher.DECRYPT_MODE, getPrivateKeyFromKeyStore());

            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully decrypted data using the algorithm '%s' and the " +
                        "Java Security API provider '%s'", algorithm, javaSecurityAPIProvider));
            }

            return cipher.doFinal(ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | BadPaddingException
                | IllegalBlockSizeException | InvalidKeyException | UnrecoverableKeyException | KeyStoreException e) {
            String errorMessage = String.format("An error occurred while decrypting using the algorithm : '%s'"
                    , algorithm);
            log.error(errorMessage);
            throw new CryptoException(errorMessage, e);
        }
    }

    private Certificate getCertificateFromStore() throws KeyStoreException {

        return keyStore.getCertificate(keyAlias);
    }

    private PrivateKey getPrivateKeyFromKeyStore() throws UnrecoverableKeyException, NoSuchAlgorithmException
            , KeyStoreException {

        Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());

        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            return null;
        }
    }
}
