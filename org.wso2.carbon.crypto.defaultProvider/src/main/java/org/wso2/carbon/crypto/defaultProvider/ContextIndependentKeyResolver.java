package org.wso2.carbon.crypto.defaultProvider;

import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.KeyResolver;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;

import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;

/**
 * The key resolver implementation which does not honour the context information other than the tenant details.
 * <p>
 * This resolver is the last resort, if none of the other resolvers are able to find key discovery information.
 * It returns discovery information which points to the primary key store.
 */
public class ContextIndependentKeyResolver extends KeyResolver {

    private static final String PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH = "Security.KeyStore.KeyAlias";
    private static final String PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH = "Security.KeyStore.KeyPassword";

    private ServerConfigurationService serverConfigurationService;

    public ContextIndependentKeyResolver(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    @Override
    public boolean isApplicable(CryptoContext cryptoContext) {

        return true;
    }

    @Override
    public PrivateKeyInfo getPrivateKeyInfo(CryptoContext cryptoContext) {

        String keyAlias;
        String keyPassword;
        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            keyAlias = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH);
            keyPassword = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_PASSWORD_PROPERTY_PATH);
        } else {
            keyAlias = cryptoContext.getTenantDomain();
            keyPassword = null; // Key password will be internally handled by the KeyStoreManager
        }

        return new PrivateKeyInfo(keyAlias, keyPassword);
    }

    @Override
    public CertificateInfo getCertificateInfo(CryptoContext cryptoContext) {

        String certificateAlias;
        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            certificateAlias = serverConfigurationService.getFirstProperty(PRIMARY_KEYSTORE_KEY_ALIAS_PROPERTY_PATH);
        } else {
            certificateAlias = cryptoContext.getTenantDomain();
        }

        return new CertificateInfo(certificateAlias, null);
    }
}
