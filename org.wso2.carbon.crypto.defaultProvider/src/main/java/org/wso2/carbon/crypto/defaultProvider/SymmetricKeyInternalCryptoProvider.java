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
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import static javax.swing.plaf.basic.BasicHTML.propertyKey;

/**
 * The symmetric key implementation of {@link InternalCryptoProvider}
 */
public class SymmetricKeyInternalCryptoProvider implements InternalCryptoProvider {

    private static Log log = LogFactory.getLog(SymmetricKeyInternalCryptoProvider.class);
    private String secretKey;

    public SymmetricKeyInternalCryptoProvider(String secretKey) {
        this.secretKey = secretKey;
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

            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(algorithm));
            return cipher.doFinal(cleartext);
        } catch (InvalidKeyException |  NoSuchPaddingException | BadPaddingException | NoSuchProviderException
                | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            String errorMessage = String.format("An error occurred while encrypting using the algorithm : '%s'"
                    , algorithm);
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

            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(algorithm));

            return cipher.doFinal(ciphertext);
        } catch (InvalidKeyException |  NoSuchPaddingException | BadPaddingException | NoSuchProviderException
                | IllegalBlockSizeException | NoSuchAlgorithmException e) {
            String errorMessage = String.format("An error occurred while decrypting using the algorithm : '%s'"
                    , algorithm);
            throw new CryptoException(errorMessage, e);
        }
    }

    private SecretKeySpec getSecretKey(String algorithm) {

        return new SecretKeySpec(secretKey.getBytes(), 0, secretKey.getBytes().length, algorithm);
    }

}
