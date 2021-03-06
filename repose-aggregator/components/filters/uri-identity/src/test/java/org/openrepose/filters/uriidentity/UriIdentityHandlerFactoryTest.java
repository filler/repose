package org.openrepose.filters.uriidentity;

import org.openrepose.commons.utils.http.PowerApiHeader;
import org.openrepose.commons.utils.http.header.HeaderName;
import org.openrepose.commons.utils.servlet.http.ReadableHttpServletResponse;
import org.openrepose.filters.uriidentity.config.IdentificationMapping;
import org.openrepose.filters.uriidentity.config.IdentificationMappingList;
import org.openrepose.filters.uriidentity.config.UriIdentityConfig;
import org.openrepose.core.filter.logic.FilterDirector;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 *
 * @author malconis
 */
public class UriIdentityHandlerFactoryTest {

    private static Double QUALITY = 0.5;
    private static String QUALITY_VALUE = ";q=0.5";
    private static String URI1 = "/someuri/1234/morestuff";
    private static String REGEX1 = ".*/[^\\d]*/(\\d*)/.*";
    private static String USER1 = "1234";
    private static String REGEX2 = ".*/[^\\d]*/abc/(.*)";
    private UriIdentityHandlerFactory factory;
    private UriIdentityConfig config;
    private HttpServletRequest request;
    private ReadableHttpServletResponse response;
    private UriIdentityHandler handler;

    @Before
    public void setUp() throws Exception {

        factory = new UriIdentityHandlerFactory();
        config = new UriIdentityConfig();
        config.setQuality(QUALITY);

        IdentificationMappingList identificationMappingList = new IdentificationMappingList();

        IdentificationMapping mapping = new IdentificationMapping();
        mapping.setId("Mapping 1");
        mapping.setIdentificationRegex(REGEX1);
        identificationMappingList.getMapping().add(mapping);

        mapping = new IdentificationMapping();
        mapping.setId("Mapping 2");
        mapping.setIdentificationRegex(REGEX2);
        identificationMappingList.getMapping().add(mapping);

        config.setIdentificationMappings(identificationMappingList);

        factory.configurationUpdated(config);

        handler = factory.buildHandler();
        request = mock(HttpServletRequest.class);
        response = mock(ReadableHttpServletResponse.class);

    }

    @Test
    public void shouldSetDefaultQuality() throws Exception {

        config = new UriIdentityConfig();
        IdentificationMappingList identificationMappingList = new IdentificationMappingList();

        IdentificationMapping mapping = new IdentificationMapping();
        mapping.setId("Mapping 1");
        mapping.setIdentificationRegex(REGEX1);
        identificationMappingList.getMapping().add(mapping);

        config.setIdentificationMappings(identificationMappingList);

        factory.configurationUpdated(config);

        handler = factory.buildHandler();

        when(request.getRequestURI()).thenReturn(URI1);

        FilterDirector result = handler.handleRequest(request, response);

        Set<String> values = result.requestHeaderManager().headersToAdd().get(HeaderName.wrap(PowerApiHeader.USER.toString()));
        assertFalse("Should have " + PowerApiHeader.USER.toString() + " header set.", values == null || values.isEmpty());

        String userName = values.iterator().next();

        assertEquals("Should find user name in header", USER1 + QUALITY_VALUE, userName);

    }
}