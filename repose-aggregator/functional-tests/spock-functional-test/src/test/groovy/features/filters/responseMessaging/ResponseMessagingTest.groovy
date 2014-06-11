package features.filters.responsemessaging

import framework.ReposeValveTest
import org.rackspace.deproxy.Deproxy
import org.rackspace.deproxy.MessageChain
import org.rackspace.deproxy.Response
import spock.lang.Shared
import spock.lang.Unroll

/**
 * ADDITIONAL SCENARIOS TO TEST:
 *
 * 1. Origin service responds with 345, 345 is configured with overwrite="IF_EMPTY", REPOSE does NOT apply RMS body
 * 2. RMS is configured to respond with a different status code than what origin service responds with
 */
class ResponseMessagingTest extends ReposeValveTest {

    def setupSpec() {
        deproxy = new Deproxy()
        deproxy.addEndpoint(properties.targetPort)

        def params = properties.getDefaultTemplateParams()
        repose.configurationProvider.applyConfigs("common", params)
        repose.configurationProvider.applyConfigs("features/filters/responsemessaging", params)
        repose.start()
        waitUntilReadyToServiceRequests()
    }

    def cleanupSpec() {
        if (deproxy) {
            deproxy.shutdown()
        }

        if (repose) {
            repose.stop()
        }
    }

    @Unroll("Repose should return expected response code #expectedResponseCode and body for #acceptType")
    def "test response body is generated by response messaging config"() {

        when: "A request is made to repose with accept type of #acceptType"
        def messageChain = deproxy.makeRequest([url: reposeEndpoint, headers: ["Accept": acceptType],
                defaultHandler: { return new Response(originServiceResponseCode, null, null, originServiceResponseBody) }])

        then: "Repose should return the expected response code"
        messageChain.receivedResponse.code == expectedResponseCode

        and: "Repose should return the expected response body"
        messageChain.receivedResponse.body == expectedResponseBody

        where:
        acceptType         | originServiceResponseCode | originServiceResponseBody | expectedResponseCode | expectedResponseBody
        "application/xml"  | 413                       | null                      | "413"                | XML_RESPONSE_413
        "application/xml"  | 403                       | null                      | "403"                | "XML Not Authorized... Syntax highlighting is magical."
        "application/json" | 405                       | null                      | "405"                | "JSON Not Authorized... The brackets are too confusing."
        "text/plain"       | 404                       | null                      | "404"                | "You are not authorized... Did you drop your ID?"
        "application/json" | 346                       | null                      | "346"                | JSON_RESPONSE_346
        "application/xml"  | 345                       | null                      | "345"                | XML_RESPONSE_345
        "application/json" | 345                       | null                      | "345"                | JSON_RESPONSE_345
        ""                 | 345                       | null                      | "345"                | JSON_RESPONSE_345
        "application/json" | 414                       | ORIGINAL_BODY             | "414"                | ORIGINAL_BODY
        "*/*"              | 503                       | null                      | "503"                | "An error has occurred. Please contact support... the printer may be on fire."
    }

    @Unroll("ResponseMessaging populates responseBody with request headers for #acceptType")
    def "test response bodies that include headers from request when accepting #acceptType"() {
        given:
        def String myDate = "Fri, 09 Mar 2012 14:56:32 GMT"


        when: "A request is made to repose with accept type of #acceptType"
        def messageChain = deproxy.makeRequest([url: reposeEndpoint, headers: ["Accept": acceptType, "MYDATE": myDate, "X-PP-Groups": "WIZARD"],
                defaultHandler: { return new Response(originServiceResponseCode, null, null, originServiceResponseBody) }])

        then: "Repose should return the expected response code"
        messageChain.receivedResponse.code == expectedResponseCode

        and: "Repose should return the expected response body"
        messageChain.receivedResponse.body == expectedResponseBody

        where:
        acceptType         | originServiceResponseCode | originServiceResponseBody | expectedResponseCode | expectedResponseBody
        "application/xml"  | 333                       | "JAWSOME"                 | "333"                | "<outer><groups>WIZARD</groups><somedate>2012-03-09T14:56:32Z</somedate></outer>"
        "application/json" | 333                       | "JAWSOME"                 | "333"                | """{ "groups": "WIZARD", "mydate": "2012-03-09T14:56:32Z" }"""
        "text/plain"       | 333                       | "JAWSOME"                 | "333"                | PLAIN_RESPONSE_333
    }

    def "When OVERWRITE == ALWAYS, ignores the requested Accept header and always returns configured ContentType"() {
        given:
        def String myDate = "Fri, 09 Mar 2012 14:56:32 GMT"

        when: "A request is made to repose with accept type of #acceptType"
        def messageChain = deproxy.makeRequest([url: reposeEndpoint, headers: ["Accept": acceptType, "MYDATE": myDate, "X-PP-Groups": "WIZARD"],
                defaultHandler: { return new Response(311, null, null, "JAWSOME") }])

        then: "Repose should return the expected response code"
        messageChain.receivedResponse.code == expectedResponseCode

        and: "Repose should return the expected response body in the media type indicated by the Accept header"
        messageChain.receivedResponse.headers.getFirstValue("Content-Type") == responseContentHeader

        where:
        acceptType         | responseContentHeader | expectedResponseCode
        "application/xml"  | "application/xml"     | "311"
        "application/json" | "application/xml"     | "311"
        "text/plain"       | "application/xml"     | "311"

    }

    def "D-12726 RMS should not throw NPE if response body is empty"() {
        when: "A request is made to repose with accept type of #acceptType"
        def messageChain = deproxy.makeRequest([url: reposeEndpoint, defaultHandler: { return new Response(200, null, null, null) }])

        then: "Repose should return the expected response code"
        messageChain.receivedResponse.code == "200"
    }

    def "Should not split request headers according to rfc"() {
        given:
        def userAgentValue = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.65 Safari/537.36"
        def reqHeaders =
            [
                    "user-agent": userAgentValue,
                    "x-pp-user": "usertest1, usertest2, usertest3",
                    "accept": "application/xml;q=1 , application/json;q=0.5"
            ]

        when: "User sends a request through repose"
        MessageChain mc = deproxy.makeRequest(url: reposeEndpoint + "/", method: 'GET', headers: reqHeaders)

        then:
        mc.handlings.size() == 1
        mc.handlings[0].request.getHeaders().findAll("user-agent").size() == 1
        mc.handlings[0].request.headers['user-agent'] == userAgentValue
        mc.handlings[0].request.getHeaders().findAll("x-pp-user").size() == 3
        mc.handlings[0].request.getHeaders().findAll("accept").size() == 2
    }

    def "Should not split response headers according to rfc"() {
        given: "Origin service returns headers "
        def respHeaders = ["location": "http://somehost.com/blah?a=b,c,d", "via": "application/xml;q=0.3, application/json;q=1"]
        def handler = { request -> return new Response(201, "Created", respHeaders, "") }

        when: "User sends a request through repose"
        MessageChain mc = deproxy.makeRequest(url: reposeEndpoint + "/", method: 'GET', defaultHandler: handler)

        then:
        mc.receivedResponse.code == "201"
        mc.handlings.size() == 1
        mc.receivedResponse.headers.findAll("location").size() == 1
        mc.receivedResponse.headers['location'] == "http://somehost.com/blah?a=b,c,d"
        mc.receivedResponse.headers.findAll("via").size() == 1
    }
    @Unroll("Requests - headers: #headerName with \"#headerValue\" keep its case")
    def "Requests - headers should keep its case in requests"() {

        when: "make a request with the given header and value"
        def headers = [
                'Content-Length': '0'
        ]
        headers[headerName.toString()] = headerValue.toString()

        MessageChain mc = deproxy.makeRequest(url: reposeEndpoint, headers: headers)

        then: "the request should keep headerName and headerValue case"
        mc.handlings.size() == 1
        mc.handlings[0].request.headers.contains(headerName)
        mc.handlings[0].request.headers.getFirstValue(headerName) == headerValue


        where:
        headerName | headerValue
        "Accept"           | "text/plain"
        "ACCEPT"           | "text/PLAIN"
        "accept"           | "TEXT/plain;q=0.2"
        "aCCept"           | "text/plain"
        "CONTENT-Encoding" | "identity"
        "Content-ENCODING" | "identity"
        //"content-encoding" | "idENtItY"
        //"Content-Encoding" | "IDENTITY"
    }

    @Unroll("Responses - headers: #headerName with \"#headerValue\" keep its case")
    def "Responses - header keep its case in responses"() {

        when: "make a request with the given header and value"
        def headers = [
                'Content-Length': '0'
        ]
        headers[headerName.toString()] = headerValue.toString()

        MessageChain mc = deproxy.makeRequest(url: reposeEndpoint, defaultHandler: { new Response(200, null, headers) })

        then: "the response should keep headerName and headerValue case"
        mc.handlings.size() == 1
        mc.receivedResponse.headers.contains(headerName)
        mc.receivedResponse.headers.getFirstValue(headerName) == headerValue


        where:
        headerName | headerValue
        "x-auth-token" | "123445"
        "X-AUTH-TOKEN" | "239853"
        "x-AUTH-token" | "slDSFslk&D"
        "x-auth-TOKEN" | "sl4hsdlg"
        "CONTENT-Type" | "application/json"
        "Content-TYPE" | "application/json"
        //"content-type" | "application/xMl"
        //"Content-Type" | "APPLICATION/xml"
    }

    @Shared
    def PLAIN_RESPONSE_333 = """X-PP-Groups: WIZARD
	    MY-DATE: 2012-03-09T14:56:32Z"""

    @Shared
    def XML_RESPONSE_413 =
        """<overLimit
    xmlns="http://docs.openstack.org/common/api/v1.1"
    code="413" retryAfter="">
  <message>OverLimit Retry...</message>
  <details>Error Details...</details>
</overLimit>""";

    @Shared
    def JSON_RESPONSE_346 = """{
    "response" : {
        "code" : 346
    }
}"""

    @Shared
    def XML_RESPONSE_345 = """<response
    xmlns="http://docs.openstack.org/common/api/v1.1"
    code="345">
  <message>Woohooo!  You got a 345!</message>
</response>"""

    @Shared
    def JSON_RESPONSE_345 = """{
    "response" : {
        "code" : 345
    }
}"""
    @Shared String ORIGINAL_BODY = "Origin Service says hello!"

}
