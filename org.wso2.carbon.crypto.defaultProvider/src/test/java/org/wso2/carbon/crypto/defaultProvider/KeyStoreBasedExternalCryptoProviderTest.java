package org.wso2.carbon.crypto.defaultProvider;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.crypto.api.ExternalCryptoProvider;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import javax.crypto.Cipher;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class KeyStoreBasedExternalCryptoProviderTest {

    public static final String KEY_STORE_FILE_NAME = "keystore.jks";
    public static final String KEY_STORE_PASSWORD = "keystore-password";
    public static final String KEY_ALIAS = "key-alias";
    public static final String KEY_PASSWORD = "key-password";

    private KeyStore keyStore;
    ExternalCryptoProvider jksCryptoProvider;
    PublicKey publicKey;
    PrivateKey privateKey;

    @BeforeClass
    public void init() throws Exception {

        keyStore = getKeyStore();
        publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
        privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
        jksCryptoProvider = new KeyStoreBasedExternalCryptoProvider();
    }

//    @Test(dataProvider = "signingAlgorithms")
//    public void testSigning(String algorithm, String javaSecurityAPIProvider) throws Exception {
//
//        int dataLength = 50;
//        byte[] data = RandomStringUtils.random(dataLength).getBytes();
//        byte[] signature = jksCryptoProvider.sign(data, algorithm, javaSecurityAPIProvider);
//
//        assertTrue(canVerifySignature(data, signature, publicKey, algorithm, javaSecurityAPIProvider));
//    }

//    @Test(dataProvider = "encryptionAlgorithms")
//    public void testEncrypting(String algorithm) throws Exception {
//
//        int plaintextLength = 50;
//        String plaintext = RandomStringUtils.random(plaintextLength);
//
//        Cipher cipher = Cipher.getInstance(algorithm);
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//
//        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
//
//        assertEquals(new String(jksCryptoProvider.decrypt(ciphertext, algorithm, null)), plaintext);
//    }

    private KeyStore getKeyStore() throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(this.getClass().getResourceAsStream(File.separator + KEY_STORE_FILE_NAME),
                KEY_STORE_PASSWORD.toCharArray());
        return keyStore;
    }

    private boolean canVerifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey, String algorithm,
                                       String javaSecurityAPIProvider) throws Exception {

        Signature signature;

        if (StringUtils.isBlank(javaSecurityAPIProvider)) {
            signature = Signature.getInstance(algorithm);
        } else {
            signature = Signature.getInstance(algorithm, javaSecurityAPIProvider);
        }

        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    /**
     * This data provider provides an array of (signing algorithm, javaSecurityAPIProvider) combinations.
     *
     * @return
     */
    @DataProvider(name = "signingAlgorithms")
    public static Object[][] getSigningAlgorithms() {

        return new Object[][]{{"SHA256withRSA", null}, {"SHA1withRSA", null}};
    }

    /**
     * This data provider provides an array of encryption algorithms.
     *
     * @return
     */
    @DataProvider(name = "encryptionAlgorithms")
    public static Object[][] getEncryptionAlgorithms() {

        return new Object[][]{{"RSA"}};
    }

}
