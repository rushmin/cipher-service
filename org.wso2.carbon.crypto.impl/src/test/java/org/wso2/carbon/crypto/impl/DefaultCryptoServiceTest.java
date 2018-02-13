package org.wso2.carbon.crypto.impl;

import org.testng.annotations.Test;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.InternalCryptoProvider;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class DefaultCryptoServiceTest {

    @Test
    public void testProviderSelection() throws Exception {

        DefaultCryptoService defaultCryptoService = new DefaultCryptoService();

        InternalCryptoProvider mockCryptoProvider = new SimpleCryptoProvider();
        defaultCryptoService.registerInternalCryptoProvider(mockCryptoProvider);

        assertTrue(defaultCryptoService.areInternalCryptoProvidersAvailable());

        assertEquals(defaultCryptoService.getMostSuitableInternalProvider(), mockCryptoProvider);

        defaultCryptoService.unregisterAllInternalCryptoProviders();

        assertFalse(defaultCryptoService.areInternalCryptoProvidersAvailable());
    }
}
