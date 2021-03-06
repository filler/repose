package framework

import org.apache.commons.io.FileUtils
import org.linkedin.util.clock.SystemClock
import org.rackspace.deproxy.Deproxy
import spock.lang.Shared
import spock.lang.Specification

import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

import static org.linkedin.groovy.util.concurrent.GroovyConcurrentUtils.waitForCondition
import org.rackspace.deproxy.MessageChain

abstract class ReposeValveTest extends Specification {

    /**
     * Used to get the JMX hostname when needing to resolve JMX stuff
     */
    @Shared
    String jmxHostname = InetAddress.getLocalHost().getHostName()

    @Shared
    def ReposeValveLauncher repose

    @Shared
    def Deproxy deproxy

    @Shared
    def TestProperties properties

    @Shared
    def ReposeLogSearch reposeLogSearch

    @Shared
    int clientId = 0

    def setupSpec() {

        properties = new TestProperties()

        switch (properties.getReposeContainer().toLowerCase()) {
            case "valve":
                configureReposeValve()
                repose.configurationProvider.cleanConfigDirectory()
                break
            case "tomcat":
                throw new UnsupportedOperationException("Please implement me")
            case "multinode":
                String glassfishJar = properties.glassfishJar
                configureReposeGlassfish(glassfishJar)
                break
            default:
                throw new UnsupportedOperationException("Unknown container: " + reposeContainer)
        }
    }

    def configureReposeGlassfish(String glassfishJar) {
        repose = new ReposeContainerLauncher(glassfishJar)
        repose.enableDebug()
    }


    def configureReposeValve() {

        ReposeConfigurationProvider reposeConfigProvider = new ReposeConfigurationProvider(properties)

        repose = new ReposeValveLauncher(reposeConfigProvider, properties)
        repose.enableDebug()
        reposeLogSearch = new ReposeLogSearch(logFile);
    }

    def cleanupSpec() {
        if (deproxy)
            deproxy.shutdown()

        if (repose?.isUp())
            repose.stop()
    }

    def cleanLogDirectory() {
        FileUtils.deleteQuietly(new File(logFile))
    }

    /**
     * This needs to be the default way to determine if repose is ready to serve requests I think...
     * @param responseCode
     * @param throwException
     * @param checkLogMessage
     * @return
     */
    def waitUntilReadyToServiceRequests(String responseCode = '200',
                                        boolean throwException = true,
                                        boolean checkLogMessage = false) {
        def clock = new SystemClock()
        def innerDeproxy = new Deproxy()
        def logSearch = new ReposeLogSearch(properties.logFile)
        if(checkLogMessage)
            logSearch.cleanLog()
        MessageChain mc
        try{
            waitForCondition(clock, '35s', '1s', {
                if(checkLogMessage &&
                        //TODO: this will not work, because of clusterID/NodeId awareness
                        //This needs to do a bit more regexp
                        // ClusterId and NodeID need to be known for what node we expect to be alive
                        // .*PowerFilter.* clusterId-nodeId: Repose Ready
                        logSearch.awaitByString(
                                "Repose ready", 1, 35, TimeUnit.SECONDS).size() > 0){
                    return true
                }
                try {
                    mc = innerDeproxy.makeRequest([url: reposeEndpoint])
                } catch (Exception e) {}
                if (mc != null) {
                    println mc.receivedResponse.code
                    return mc.receivedResponse.code.equals(responseCode)
                } else {
                    return false
                }
            })
        } catch (TimeoutException exc){
            if(throwException){
                throw exc
            }else{
                return false
            }
        }

    }

    // Helper methods to minimize refactoring in all test classes
    def getReposeEndpoint() {
        return properties.getReposeEndpoint()
    }

    def getConnFramework() {
        return properties.getConnFramework()
    }

    def getConfigTemplates() {
        return properties.getConfigTemplates()
    }

    def getConfigDirectory() {
        return properties.getConfigDirectory()
    }

    def getLogFile() {
        return properties.getLogFile()
    }

    def getReposeContainer() {
        return properties.getReposeContainer()
    }


}
