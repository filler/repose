package features.core.classloader

import framework.ReposeConfigurationProvider
import framework.ReposeValveLauncher
import framework.ReposeValveTest
import org.junit.Assume
import org.rackspace.deproxy.Deproxy
import org.rackspace.deproxy.MessageChain


class ClassLoaderTest extends ReposeValveTest {
    static int originServicePort
    static int reposePort
    static String url
    static ReposeConfigurationProvider reposeConfigProvider

    /**
     * Unfortunately this tests requires the Servlet Filter Contract to actually be upheld,
     * Repose doesn't do this, so we're setting a timebomb that will make the tests fail at a later date
     */
    def splodeDate = new GregorianCalendar(2015, Calendar.JUNE, 1)


    /**
     * copy the bundle from /repose-aggregator/functional-tests/test-bundles/bundle-one/target/
     * and copy the bundle from /repose-aggregator/functional-tests/test-bundles/bundle-two/target/
     * to artifacts directory
     *
     * set up config that has in system model:
     *  filter-one
     *  filter-two
     *
     * start repose with the launcher
     * make a request with header foo. validate that header bar returns
     * make a request with another header.  validate we get a failure back
     *
     * Test Scenario #1: An ear file can access a dependency that is not present in another ear.
     * 1. Create a simple class place it in a jar (JAR 1) which contains a method "createBAR" that returns the string "BAR"
     * 2. EAR 1 has class as a dependency
     * 3. EAR 1 contains a request wrapper the wrapper intercepts calls to get HEADER if the header is "FOO", then the wrapper makes a call to createBAR in the dependent class and returns it's result
     * 4. EAR 1 contains the Foo filter which simply wraps the request and sends it down the chain.
     * 5. EAR 2 contains a filter that simply calls the request and gets the "FOO" header – the expected result is to get "BAR"...otherwise fail.
     * 6. Place both filters in system model EAR 1 filter before EAR 2 Filter
     * 7. Send a request that DOES NOT contain the FOO header
     * 8. That contains a FOO header with a value other than "BAR"
     *
     */
    def "An ear file can access a dependency that is not present in another ear"(){
        Assume.assumeTrue(new Date() > splodeDate.getTime())

        deproxy = new Deproxy()
        originServicePort = properties.targetPort
        deproxy.addEndpoint(originServicePort)

        reposePort = properties.reposePort
        url = "http://localhost:${reposePort}"

        reposeConfigProvider = new ReposeConfigurationProvider(configDirectory, configTemplates)
        repose = new ReposeValveLauncher(
                reposeConfigProvider,
                properties.getReposeJar(),
                url,
                properties.getConfigDirectory(),
                reposePort
        )
        repose.enableDebug()

        def params = properties.getDefaultTemplateParams()

        reposeConfigProvider.cleanConfigDirectory()
        reposeConfigProvider.applyConfigs("common", params)
        reposeConfigProvider.applyConfigs("features/core/classloader/one", params)

        repose.start(killOthersBeforeStarting: false,
                waitOnJmxAfterStarting: false)

        repose.waitForNon500FromUrl(url)
        when: "make a request with the FOO header"
        def headers = [
                'FOO': 'stuff'
        ]

        MessageChain mc = deproxy.makeRequest(url: url, headers: headers)


        then: "the request header should equal BAR"
        mc.handlings.size() == 1
        mc.receivedResponse.code == 200
        mc.handlings[0].request.headers.getFirstValue("FOO") == "BAR"

        when: "make a request with the BAR header"
        headers = [
                'BAR': 'stuff'
        ]

        mc = deproxy.makeRequest(url: url, headers: headers)


        then: "the request should bomb"
        mc.handlings.size() == 0
        mc.receivedResponse.code == 500
        reposeLogSearch.searchByString("IllegalArgumentException").size() > 0
    }

    /**
     * copy the bundle from /repose-aggregator/functional-tests/test-bundles/bundle-one/target/
     * and copy the bundle from /repose-aggregator/functional-tests/test-bundles/bundle-three/target/
     * to artifacts directory
     *
     * set up config that has in system model:
     *  filter-one
     *  filter-three
     *
     * Test Scenario #2: An ear file cannot access a dependency from another ear on its own
     * 1. EAR 3 : contains a filter that simply tries to instantiate the simple class create in filter 1.
     *   The filter does not list the jar as a dependency. (using class.forName to try to instantiate a string)
     * 2. Place EAR 1 before EAR 3 in the system model
     * 3. Send a request
     * 4. Expected result is ClassNotFound
     */
    def "Ensure filter three (in filter-bundle-three) cannot reach a dependency in filter-bundle-one"(){
        deproxy = new Deproxy()
        originServicePort = properties.targetPort
        deproxy.addEndpoint(originServicePort)

        reposePort = properties.reposePort
        url = "http://localhost:${reposePort}"

        reposeConfigProvider = new ReposeConfigurationProvider(configDirectory, configTemplates)
        repose = new ReposeValveLauncher(
                reposeConfigProvider,
                properties.getReposeJar(),
                url,
                properties.getConfigDirectory(),
                reposePort
        )
        repose.enableDebug()

        def params = properties.getDefaultTemplateParams()

        reposeConfigProvider.cleanConfigDirectory()
        reposeConfigProvider.applyConfigs("common", params)
        reposeConfigProvider.applyConfigs("features/core/classloader/two", params)

        repose.start()

        when: "make a request with the FOO header"
        def headers = [
                'FOO': 'stuff'
        ]

        MessageChain mc = deproxy.makeRequest(url: url, headers: headers)

        then: "The filter traps the exception and returns successfully"
        mc.handlings.size() == 1
        mc.receivedResponse.code == "200"
    }

    /**
     * copy the bundle from /repose-aggregator/functional-tests/test-bundles/bundle-four/target/
     * and copy the bundle from /repose-aggregator/functional-tests/test-bundles/bundle-five/target/
     * to artifacts directory
     *
     * set up config that has in system model:
     *  filter-one
     *  filter-two
     *
     * start repose with the launcher
     * make a request with header foo. validate that BAR is logged in repose.log
     * validate that BARRR is logged in repose.log
     */

    def "test class loader three"(){
        Assume.assumeTrue(new Date() > splodeDate.getTime())
        deproxy = new Deproxy()
        originServicePort = properties.targetPort
        deproxy.addEndpoint(originServicePort)

        reposePort = properties.reposePort
        url = "http://localhost:${reposePort}"

        reposeConfigProvider = new ReposeConfigurationProvider(configDirectory, configTemplates)
        repose = new ReposeValveLauncher(
                reposeConfigProvider,
                properties.getReposeJar(),
                url,
                properties.getConfigDirectory(),
                reposePort
        )
        repose.enableDebug()

        def params = properties.getDefaultTemplateParams()

        reposeConfigProvider.cleanConfigDirectory()
        reposeConfigProvider.applyConfigs("common", params)
        reposeConfigProvider.applyConfigs("features/core/classloader/two", params)

        repose.start(killOthersBeforeStarting: false,
                waitOnJmxAfterStarting: false)

        repose.waitForNon500FromUrl(url)

        when: "make a request with the FOO header"
        def headers = [
                'FOO': 'stuff'
        ]

        MessageChain mc = deproxy.makeRequest(url: url, headers: headers)


        then: "the request should log BAR and BARRR"
        mc.handlings.size() == 1
        mc.receivedResponse.code == 200
        reposeLogSearch.searchByString("BAR").size() == 2
        reposeLogSearch.searchByString("BARRR").size() == 1
    }

    def cleanup(){
        if (repose) {
            repose.stop()
        }
        if (deproxy) {
            deproxy.shutdown()
        }
    }
}
