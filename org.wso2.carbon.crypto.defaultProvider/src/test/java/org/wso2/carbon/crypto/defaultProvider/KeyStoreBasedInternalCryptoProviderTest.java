package org.wso2.carbon.crypto.defaultProvider;

import org.apache.commons.lang.RandomStringUtils;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class KeyStoreBasedInternalCryptoProviderTest {

    public static final String KEY_STORE_FILE_NAME = "keystore.jks";
    public static final String KEY_STORE_PASSWORD = "keystore-password";
    public static final String KEY_ALIAS = "key-alias";
    public static final String KEY_PASSWORD = "key-password";

    private KeyStore keyStore;
    KeyStoreBasedInternalCryptoProvider jksCryptoProvider;
    PublicKey publicKey;
    PrivateKey privateKey;

    @BeforeClass
    public void init() throws Exception {

        keyStore = getKeyStore();
        publicKey = keyStore.getCertificate(KEY_ALIAS).getPublicKey();
        privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
        jksCryptoProvider = new KeyStoreBasedInternalCryptoProvider(keyStore, KEY_ALIAS, KEY_PASSWORD);
    }

    @Test(dataProvider = "encryptionAlgorithms")
    public void testDecrypting(String algorithm) throws Exception {

        int plaintextLength = 50;
        String plaintext = RandomStringUtils.random(plaintextLength);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        assertEquals(new String(jksCryptoProvider.decrypt(ciphertext, algorithm, null)), plaintext);
    }

    @Test(dataProvider = "encryptionAlgorithms")
    public void testEncrypting(String algorithm) throws Exception {

        int plaintextLength = 50;
        String plaintext = RandomStringUtils.random(plaintextLength);

        byte[] ciphertext = jksCryptoProvider.encrypt(plaintext.getBytes(), algorithm, null);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        assertEquals(new String(cipher.doFinal(ciphertext)), plaintext);
    }

    private KeyStore getKeyStore() throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(this.getClass().getResourceAsStream(File.separator + KEY_STORE_FILE_NAME),
                KEY_STORE_PASSWORD.toCharArray());
        return keyStore;
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
