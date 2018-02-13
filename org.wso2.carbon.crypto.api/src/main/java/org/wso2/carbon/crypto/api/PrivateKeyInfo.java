package org.wso2.carbon.crypto.api;

/**
 * A simple data holder class which is used to encapsulate discovery information about a private key.
 */
public class PrivateKeyInfo {

    private String keyAlias;
    private String keyPassword;

    public PrivateKeyInfo(String keyAlias, String keyPassword) {

        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword;
    }

    public String getKeyAlias() {

        return keyAlias;
    }

    public String getKeyPassword() {

        return keyPassword;
    }

    @Override
    public String toString() {

        return "PrivateKeyInfo{" +
                "keyAlias='" + keyAlias + '\'' +
                '}';
    }
}
