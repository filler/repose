package org.openrepose.core.services.httpclient.impl

import org.junit.Before
import org.junit.Test
import org.openrepose.commons.config.resource.ConfigurationResource
import org.openrepose.commons.config.resource.ConfigurationResourceResolver
import org.openrepose.core.service.httpclient.config.HttpConnectionPoolConfig
import org.openrepose.core.services.config.ConfigurationService
import org.openrepose.core.services.healthcheck.HealthCheckService
import org.openrepose.core.services.healthcheck.HealthCheckServiceProxy
import org.openrepose.core.services.healthcheck.Severity

import static org.mockito.Matchers.any
import static org.mockito.Matchers.anyString
import static org.mockito.Mockito.*

class HttpConnectionPoolImplTest {

    HttpConnectionPoolServiceImpl httpConnectionPoolService
    HealthCheckService healthCheckService
    HealthCheckServiceProxy healthCheckServiceProxy
    ConfigurationService configurationService;

    @Before
    void setUp() {
        configurationService = mock(ConfigurationService.class)
        healthCheckService = mock(HealthCheckService.class)
        healthCheckServiceProxy = mock(HealthCheckServiceProxy)
        when(healthCheckService.register()).thenReturn(healthCheckServiceProxy)

        httpConnectionPoolService = new HttpConnectionPoolServiceImpl(configurationService, healthCheckService)
    }

    @Test
    void verifyRegistrationToHealthCheckService() {
        verify(healthCheckService, times(1)).register()
    }

    @Test
    void verifyInitialReportOfConfig() {
        ConfigurationResourceResolver resourceResolver = mock(ConfigurationResourceResolver.class);
        ConfigurationResource configurationResource = mock(ConfigurationResource.class);
        when(configurationService.getResourceResolver()).thenReturn(resourceResolver);
        when(resourceResolver.resolve(HttpConnectionPoolServiceImpl.DEFAULT_CONFIG_NAME)).thenReturn(configurationResource);
        when(configurationService.getResourceResolver().resolve(HttpConnectionPoolServiceImpl.DEFAULT_CONFIG_NAME)).thenReturn(configurationResource);

        httpConnectionPoolService.init()
        verify(healthCheckServiceProxy, times(1)).reportIssue(any(String), any(String), any(Severity.class));
    }

    @Test
    void verifyConfigurationUpdated() {

        ConfigurationResourceResolver resourceResolver = mock(ConfigurationResourceResolver.class);
        ConfigurationResource configurationResource = mock(ConfigurationResource.class);
        when(configurationService.getResourceResolver()).thenReturn(resourceResolver);
        when(resourceResolver.resolve(HttpConnectionPoolServiceImpl.DEFAULT_CONFIG_NAME)).thenReturn(configurationResource);
        when(configurationService.getResourceResolver().resolve(HttpConnectionPoolServiceImpl.DEFAULT_CONFIG_NAME)).thenReturn(configurationResource);

        httpConnectionPoolService.configurationListener.configurationUpdated(mock(HttpConnectionPoolConfig))

        assert (httpConnectionPoolService.configurationListener.initialized)
        verify(healthCheckServiceProxy, times(1)).resolveIssue(anyString());
    }
}
