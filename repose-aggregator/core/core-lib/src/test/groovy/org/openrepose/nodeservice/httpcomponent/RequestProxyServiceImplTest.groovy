package org.openrepose.nodeservice.httpcomponent

import org.apache.http.HttpEntity
import org.apache.http.HttpResponse
import org.apache.http.StatusLine
import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpPatch
import org.mockito.ArgumentCaptor
import org.mockito.Mockito
import org.openrepose.core.services.config.ConfigurationService
import org.openrepose.core.services.healthcheck.HealthCheckService
import org.openrepose.core.services.httpclient.HttpClientResponse
import org.openrepose.core.services.httpclient.HttpClientService
import spock.lang.Specification

import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

class RequestProxyServiceImplTest extends Specification {
    RequestProxyServiceImpl requestProxyService
    HttpClient httpClient

    def setup() {
        httpClient = mock(HttpClient)
        HttpClientResponse httpClientResponse = mock(HttpClientResponse)
        when(httpClientResponse.getHttpClient()).thenReturn(httpClient)
        HttpClientService httpClientService = mock(HttpClientService)
        when(httpClientService.getClient(Mockito.any(String))).thenReturn(httpClientResponse)
        requestProxyService = new RequestProxyServiceImpl(
                mock(ConfigurationService.class),
                mock(HealthCheckService.class),
                httpClientService,
                "cluster",
                "node")
    }

    def "Send a patch request with expected body and headers and return expected response"() {
        given:
        StatusLine statusLine = mock(StatusLine)
        when(statusLine.getStatusCode()).thenReturn(418)
        HttpEntity httpEntity = mock(HttpEntity)
        when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream([1, 2, 3] as byte[]))
        HttpResponse httpResponse = mock(HttpResponse)
        when(httpResponse.getStatusLine()).thenReturn(statusLine)
        when(httpResponse.getEntity()).thenReturn(httpEntity)
        ArgumentCaptor<HttpPatch> captor = ArgumentCaptor.forClass(HttpPatch)
        when(httpClient.execute(captor.capture())).thenReturn(httpResponse)

        when:
        byte[] sentBytes = [4, 5, 6] as byte[]
        def response = requestProxyService.patch("http://www.google.com", "key", ["thing": "other thing"], sentBytes)
        def request = captor.getValue()
        byte[] readBytes = new byte[3]
        request.getEntity().getContent().read(readBytes)
        byte[] returnedBytes = new byte[3]
        response.data.read(returnedBytes)

        then:
        request.getMethod() == "PATCH"
        request.getURI().toString() == "http://www.google.com/key"
        request.getHeaders("thing").first().value == "other thing"
        readBytes == sentBytes

        response.status == 418
        returnedBytes == [1, 2, 3] as byte[]
    }
}
