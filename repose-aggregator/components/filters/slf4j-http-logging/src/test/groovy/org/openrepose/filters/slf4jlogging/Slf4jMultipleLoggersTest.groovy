package org.openrepose.filters.slf4jlogging

import com.mockrunner.mock.web.MockFilterChain
import com.mockrunner.mock.web.MockHttpServletRequest
import com.mockrunner.mock.web.MockHttpServletResponse
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.core.LoggerContext
import org.apache.logging.log4j.test.appender.ListAppender
import spock.lang.Ignore
import spock.lang.Shared
import spock.lang.Specification

@Ignore
class Slf4jMultipleLoggersTest extends Specification {
    ListAppender app1
    ListAppender app2
    ListAppender app3

    @Shared
    Slf4jHttpLoggingFilter filter

    def setupSpec() {
        System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                "com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl");
        filter = Slf4jLoggingFilterTestUtil.configureFilter([
                //Configure a logger with all the things so I can verify all the things we claim to support
                Slf4jLoggingFilterTestUtil.logConfig("Logger1", "%r"),
                Slf4jLoggingFilterTestUtil.logConfig("Logger2", "%m"),
                Slf4jLoggingFilterTestUtil.logConfig("Logger3", "%a")
        ])
    }

    def setup() {
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false)
        app1 = ((ListAppender)(ctx.getConfiguration().getAppender("List1"))).clear()
        app2 = ((ListAppender)(ctx.getConfiguration().getAppender("List2"))).clear()
        app3 = ((ListAppender)(ctx.getConfiguration().getAppender("List3"))).clear()
    }

    def "The SLF4j logging filter logs to the named loggers"(){
        given:
        MockFilterChain chain = new MockFilterChain()
        MockHttpServletRequest request = new MockHttpServletRequest()
        MockHttpServletResponse response = new MockHttpServletResponse()

        //Will need to set up the request and response to verify the log line
        request.setRequestURI("http://www.example.com/derp/derp?herp=derp")
        request.setRequestURL("http://www.example.com/derp/derp?herp=derp")
        request.addHeader("Accept", "application/xml")
        request.setQueryString("?herp=derp")
        request.setMethod("GET")
        request.setRemoteHost("10.10.220.221")
        request.setLocalAddr("10.10.220.220")
        request.setLocalPort(12345)
        request.setServerPort(8080)
        request.addHeader("X-PP-User", "leUser") //Remote user is special for Repose...


        def responseBody = "HEY A BODY"
        response.setContentLength(10)// size of responseBody .. but no
        response.setStatus(200,"OK")
        response.addHeader("X-Derp-header", "lolwut")
        response.getWriter().print(responseBody)
        response.getWriter().flush()
        response.getWriter().close() //I think this should shove the body in there

        when:
        filter.doFilter(request, response, chain)

        then:
        chain.getRequestList().size() == 1

        app1.getEvents().size() == 1
        app1.getEvents().find { it.getMessage().getFormattedMessage() == "GET http://www.example.com/derp/derp?herp=derp HTTP/1.1" }

        app2.getEvents().size() == 1
        app2.getEvents().find { it.getMessage().getFormattedMessage() == "GET" }

        app3.getEvents().size() == 1
        app3.getEvents().find { it.getMessage().getFormattedMessage() == "127.0.0.1" }
    }
}
