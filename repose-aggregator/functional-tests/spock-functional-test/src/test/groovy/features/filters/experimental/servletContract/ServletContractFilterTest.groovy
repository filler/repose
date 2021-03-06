package features.filters.experimental.servletContract

import framework.ReposeValveTest
import org.junit.Assume
import org.rackspace.deproxy.Deproxy
import org.rackspace.deproxy.MessageChain
import org.rackspace.deproxy.Response

class ServletContractFilterTest extends ReposeValveTest {

    def splodeDate = new GregorianCalendar(2015, Calendar.JUNE, 1)

    /**
     * This test fails because repose does not properly support the servlet filter contract.
     * It should not fail.
     *
     * This test is currently ignored until the splodeDate.
     *
     * It should be corrected in REP-320:
     * https://repose.atlassian.net/browse/REP-320
     */
    def "Proving that a custom filter (although tightly coupled) does in fact work" () {
        setup:
        Assume.assumeTrue(new Date() > splodeDate.getTime())

        def params = properties.defaultTemplateParams
        repose.configurationProvider.applyConfigs("common", params)
        repose.configurationProvider.applyConfigs("features/filters/experimental/servletcontract", params)

        deproxy = new Deproxy()
        deproxy.addEndpoint(properties.targetPort)
        def started = true
        repose.start([waitOnJmxAfterStarting: false])

        waitUntilReadyToServiceRequests("200", false, true)

        when:
        MessageChain mc = null
        mc = deproxy.makeRequest(
                [
                        method: 'GET',
                        url:reposeEndpoint + "/get",
                        defaultHandler: {
                            new Response(200, null, null, "This should be the body")
                        }
                ])


        then:
        mc.receivedResponse.code == '200'
        mc.receivedResponse.body.contains("<extra> Added by TestFilter, should also see the rest of the content </extra>")
        println(mc.receivedResponse.body)

        cleanup:
        if(started)
            repose.stop()
        if(deproxy != null)
            deproxy.shutdown()

    }
}
