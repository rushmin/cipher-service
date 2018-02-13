package org.wso2.carbon.crypto.api;

/**
 * The service contract of an implementation of a key resolver.
 * <p>
 * Key resolvers are used to find the discovery information of keys / certificate, based on the given context.
 */
public abstract class KeyResolver {

    private int priority;

    /**
     * Returns the resolver priority.
     *
     * @return The resolver priority.
     */
    public int getPriority() {

        return priority;
    }

    /**
     * Sets the resolver priority.
     *
     * @param priority The resolver priority.
     */
    public void setPriority(int priority) {

        this.priority = priority;
    }

    /**
     * Checks whether this resolver is applicable for the given context.
     *
     * @param cryptoContext The context information
     * @return true if the resolver is applicable, false otherwise.
     */
    public abstract boolean isApplicable(CryptoContext cryptoContext);

    /**
     * Returns the discovery information about a private key, based on the given context.
     *
     * @param cryptoContext The context information.
     * @return The discovery information about the private key.
     */
    public abstract PrivateKeyInfo getPrivateKeyInfo(CryptoContext cryptoContext);

    /**
     * Returns the discovery information about a certificate, based on the given context.
     *
     * @param cryptoContext The context information.
     * @return The discovery information about the certificate.
     */
    public abstract CertificateInfo getCertificateInfo(CryptoContext cryptoContext);

    @Override
    public String toString() {
        return String.format("%s{priority=%d}", this.getClass().getCanonicalName(), this.priority);
    }
}
