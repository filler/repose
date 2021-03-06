package org.openrepose.powerfilter;

import com.google.common.base.Optional;
import org.openrepose.commons.config.manager.UpdateListener;
import org.openrepose.commons.utils.servlet.http.MutableHttpServletRequest;
import org.openrepose.commons.utils.servlet.http.MutableHttpServletResponse;
import org.openrepose.core.ResponseCode;
import org.openrepose.core.filter.SystemModelInterrogator;
import org.openrepose.core.proxy.ServletContextWrapper;
import org.openrepose.core.services.RequestProxyService;
import org.openrepose.core.services.config.ConfigurationService;
import org.openrepose.core.services.context.container.ContainerConfigurationService;
import org.openrepose.core.services.deploy.ApplicationDeploymentEvent;
import org.openrepose.core.services.event.PowerFilterEvent;
import org.openrepose.core.services.event.common.Event;
import org.openrepose.core.services.event.common.EventListener;
import org.openrepose.core.services.event.common.EventService;
import org.openrepose.core.services.headers.response.ResponseHeaderService;
import org.openrepose.core.services.healthcheck.HealthCheckService;
import org.openrepose.core.services.healthcheck.HealthCheckServiceProxy;
import org.openrepose.core.services.healthcheck.Severity;
import org.openrepose.core.services.jmx.ConfigurationInformation;
import org.openrepose.core.services.reporting.ReportingService;
import org.openrepose.core.services.reporting.metrics.MeterByCategory;
import org.openrepose.core.services.reporting.metrics.MetricsService;
import org.openrepose.core.services.rms.ResponseMessageService;
import org.openrepose.core.spring.ReposeSpringProperties;
import org.openrepose.core.systemmodel.*;
import org.openrepose.powerfilter.filtercontext.FilterContext;
import org.openrepose.powerfilter.filtercontext.FilterContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.DelegatingFilterProxy;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * This class implements the Filter API and is managed by the servlet container.  This filter then loads
 * and runs the FilterChain which contains the individual filter instances listed in the system-model.cfg.xml.
 * <p/>
 * This class current instruments the response codes coming from Repose.
 * <p/>
 * THen the application context must be handed down into things that need it to build filters.
 * TODO: this also needs to check the properties to make sure they exist before we start up like the empty servlet used
 * to do.
 */
@Named("powerFilter")
public class PowerFilter extends DelegatingFilterProxy {
    private static final Logger LOG = LoggerFactory.getLogger(PowerFilter.class);
    public static final String SYSTEM_MODEL_CONFIG_HEALTH_REPORT = "SystemModelConfigError";
    public static final String APPLICATION_DEPLOYMENT_HEALTH_REPORT = "ApplicationDeploymentError";

    private final Object configurationLock = new Object();
    private final EventListener<ApplicationDeploymentEvent, List<String>> applicationDeploymentListener;
    private final UpdateListener<SystemModel> systemModelConfigurationListener;
    private final HealthCheckService healthCheckService;
    private final ContainerConfigurationService containerConfigurationService;
    private final ResponseMessageService responseMessageService;
    private final EventService eventService;
    private final FilterContextFactory filterContextFactory;

    private final AtomicReference<SystemModel> currentSystemModel = new AtomicReference<>();
    private final AtomicReference<PowerFilterRouter> powerFilterRouter = new AtomicReference<>();
    private final AtomicReference<List<FilterContext>> currentFilterChain = new AtomicReference<>();

    private ReportingService reportingService;
    private HealthCheckServiceProxy healthCheckServiceProxy;
    private MeterByCategory mbcResponseCodes;
    private ResponseHeaderService responseHeaderService;

    private final String nodeId;
    private final String clusterId;
    private final PowerFilterRouterFactory powerFilterRouterFactory;
    private final ConfigurationService configurationService;
    private final MetricsService metricsService;
    private final ConfigurationInformation configurationInformation;
    private final RequestProxyService requestProxyService;

    /**
     * OMG SO MANY INJECTED THINGIES
     * TODO: make this less complex
     * @param clusterId this PowerFilter's cluster ID
     * @param nodeId this PowerFilter's node ID
     * @param powerFilterRouterFactory Builds a powerfilter router for this power filter
     * @param reportingService
     * @param healthCheckService
     * @param responseHeaderService
     * @param configurationService For monitoring config files
     * @param eventService
     * @param metricsService
     * @param containerConfigurationService
     * @param responseMessageService the response message service
     * @param filterContextFactory A factory that builds filter contexts
     * @param configurationInformation allows JMX to see when this powerfilter is ready
     * @param requestProxyService Only needed by the servletconfigwrapper thingy, no other way to get it in there
     */
    @Inject
    public PowerFilter(
            @Value(ReposeSpringProperties.NODE.CLUSTER_ID) String clusterId,
            @Value(ReposeSpringProperties.NODE.NODE_ID) String nodeId,
            PowerFilterRouterFactory powerFilterRouterFactory,
            ReportingService reportingService,
            HealthCheckService healthCheckService,
            ResponseHeaderService responseHeaderService,
            ConfigurationService configurationService,
            EventService eventService,
            MetricsService metricsService,
            ContainerConfigurationService containerConfigurationService,
            ResponseMessageService responseMessageService,
            FilterContextFactory filterContextFactory,
            ConfigurationInformation configurationInformation,
            RequestProxyService requestProxyService
    ) {
        this.clusterId = clusterId;
        this.nodeId = nodeId;
        this.powerFilterRouterFactory = powerFilterRouterFactory;
        this.configurationService = configurationService;
        this.metricsService = metricsService;
        this.configurationInformation = configurationInformation;
        this.requestProxyService = requestProxyService;

        // Set up the configuration listeners
        systemModelConfigurationListener = new SystemModelConfigListener();
        applicationDeploymentListener = new ApplicationDeploymentEventListener();

        this.responseHeaderService = responseHeaderService;
        this.reportingService = reportingService;
        this.containerConfigurationService = containerConfigurationService;
        this.responseMessageService = responseMessageService;
        this.eventService = eventService;
        this.filterContextFactory = filterContextFactory;

        this.healthCheckService = healthCheckService;

        healthCheckServiceProxy = healthCheckService.register();
        mbcResponseCodes = metricsService.newMeterByCategory(ResponseCode.class, "Repose", "Response Code", TimeUnit.SECONDS);
    }

    private class ApplicationDeploymentEventListener implements EventListener<ApplicationDeploymentEvent, List<String>> {

        @Override
        public void onEvent(Event<ApplicationDeploymentEvent, List<String>> e) {
            LOG.info("{}:{} -- Application collection has been modified. Application that changed: {}", clusterId, nodeId, e.payload());

            // Using a set instead of a list to have a deployment health report if there are multiple artifacts with the same name
            Set<String> uniqueArtifacts = new HashSet<>();
            try {
                for (String artifactName : e.payload()) {
                    uniqueArtifacts.add(artifactName);
                }
                healthCheckServiceProxy.resolveIssue(APPLICATION_DEPLOYMENT_HEALTH_REPORT);
            } catch (IllegalArgumentException exception) {
                healthCheckServiceProxy.reportIssue(APPLICATION_DEPLOYMENT_HEALTH_REPORT, "Please review your artifacts directory, multiple " +
                        "versions of the same artifact exist!", Severity.BROKEN);
                LOG.error("Please review your artifacts directory, multiple versions of same artifact exists.");
            }

            configurationHeartbeat();
        }
    }

    private class SystemModelConfigListener implements UpdateListener<SystemModel> {

        private boolean isInitialized = false;

        @Override
        public void configurationUpdated(SystemModel configurationObject) {
            //TODO: how did I get here, when I've unsubscribed!
            LOG.debug("{}:{} New system model configuration provided", clusterId, nodeId);
            SystemModel previousSystemModel = currentSystemModel.getAndSet(configurationObject);
            //TODO: is this wrong?
            if (previousSystemModel == null) {
                LOG.debug("{}:{} -- issuing POWER_FILTER_CONFIGURED event from a configuration update", clusterId, nodeId);
                eventService.newEvent(PowerFilterEvent.POWER_FILTER_CONFIGURED, System.currentTimeMillis());
            }

            configurationHeartbeat();
            isInitialized = true;
        }

        @Override
        public boolean isInitialized() {
            return isInitialized;
        }
    }

    /**
     * Triggered each time the event service triggers an app deploy and when the system model is updated.
     */
    private void configurationHeartbeat() {
        if (currentSystemModel.get() != null) {
            synchronized (configurationLock) {
                SystemModelInterrogator interrogator = new SystemModelInterrogator(clusterId, nodeId);
                SystemModel systemModel = currentSystemModel.get();

                Optional<Node> localNode = interrogator.getLocalNode(systemModel);
                Optional<ReposeCluster> localCluster = interrogator.getLocalCluster(systemModel);
                Optional<Destination> defaultDestination = interrogator.getDefaultDestination(systemModel);

                if (localNode.isPresent() && localCluster.isPresent() && defaultDestination.isPresent()) {
                    ReposeCluster serviceDomain = localCluster.get();
                    Destination defaultDst = defaultDestination.get();

                    healthCheckServiceProxy.resolveIssue(SYSTEM_MODEL_CONFIG_HEALTH_REPORT);
                    try {
                        //Use the FilterContextFactory to get us a new filter chain
                        //Sometimes we won't have any filters
                        FilterList listOfFilters = localCluster.get().getFilters();

                        //Only if we've been configured with some filters should we get a new list
                        List<FilterContext> newFilterChain;
                        if (listOfFilters != null) {
                            //TODO: sometimes there isn't any FilterConfig available, and it'll be null...
                            newFilterChain = filterContextFactory.buildFilterContexts(getServletContext(), listOfFilters.getFilter());
                        } else {
                            //Running with no filters is a totally valid use case!
                            newFilterChain = Collections.emptyList();
                        }

                        List<FilterContext> oldFilterChain = currentFilterChain.getAndSet(newFilterChain);

                        powerFilterRouter.set(powerFilterRouterFactory.
                                getPowerFilterRouter(serviceDomain, localNode.get(), getServletContext(), defaultDst.getId()));

                        //Destroy all the old filters
                        if (oldFilterChain != null) {
                            for (FilterContext ctx : oldFilterChain) {
                                ctx.destroy();
                            }
                        }

                        if(LOG.isDebugEnabled()) {
                            List<String> filterChainInfo = new LinkedList<>();
                            for(FilterContext ctx :newFilterChain) {
                                filterChainInfo.add(ctx.getName() + "-" + ctx.getFilter().getClass().getName());
                            }
                            LOG.debug("{}:{} -- Repose filter chain: {}", clusterId, nodeId, filterChainInfo);
                        }

                        //Only log this repose ready if we're able to properly fire up a new filter chain
                        LOG.info("{}:{} -- Repose ready", clusterId, nodeId);
                        //Update the JMX bean with our status
                        configurationInformation.updateNodeStatus(clusterId, nodeId, true);
                    } catch (FilterInitializationException fie) {
                        LOG.error("{}:{} -- Unable to create new filter chain.", clusterId, nodeId, fie);
                        //Update the JMX bean with our status
                        configurationInformation.updateNodeStatus(clusterId, nodeId, false);
                    } catch (PowerFilterChainException e) {
                        LOG.error("{}:{} -- Unable to initialize filter chain builder.", clusterId, nodeId, e);
                        //Update the JMX bean with our status
                        configurationInformation.updateNodeStatus(clusterId, nodeId, false);
                    }
                } else {
                    LOG.error("{}:{} -- Unhealthy system-model config (cannot identify local node, or no default destination) - please check your system-model.cfg.xml", clusterId, nodeId);
                    healthCheckServiceProxy.reportIssue(SYSTEM_MODEL_CONFIG_HEALTH_REPORT, "Unable to identify the " +
                            "local host in the system model, or no default destination - please check your system-model.cfg.xml", Severity.BROKEN);
                }
            }
        }
    }

    @Override
    public void initFilterBean() {
        LOG.info("{}:{} -- Initializing PowerFilter bean", clusterId, nodeId);

        /**
         * http://docs.spring.io/spring-framework/docs/3.1.4.RELEASE/javadoc-api/org/springframework/web/filter/GenericFilterBean.html#setServletContext%28javax.servlet.ServletContext%29
         * Configure the servlet Context wrapper insanity to get to the Request Dispatcher I think...
         * NOTE: this thing alone provides the dispatcher for forwarding requests. It's really kind of gross.
         * we should seriously consider doing it in a ProxyServlet or something. Far less complicated.
         * getFilterConfig might be null sometimes, so just wrap it with existing servlet context
         *
         * TODO: this is broke if we set the container to create the FilterConfig, of course that doesn't give us a filterConfig either...
         */
        ServletContextWrapper wrappedServletContext = new ServletContextWrapper(getServletContext(), requestProxyService);
        setServletContext(wrappedServletContext);

        eventService.listen(applicationDeploymentListener, ApplicationDeploymentEvent.APPLICATION_COLLECTION_MODIFIED);

        URL xsdURL = getClass().getResource("/META-INF/schema/system-model/system-model.xsd");
        configurationService.subscribeTo("", "system-model.cfg.xml", xsdURL, systemModelConfigurationListener, SystemModel.class);
    }

    @Override
    public void destroy() {
        healthCheckServiceProxy.deregister();
        LOG.info("{}:{} -- Destroying PowerFilter bean", clusterId, nodeId);
        eventService.squelch(applicationDeploymentListener, ApplicationDeploymentEvent.APPLICATION_COLLECTION_MODIFIED);
        configurationService.unsubscribeFrom("system-model.cfg.xml", systemModelConfigurationListener);

        //TODO: do we need to synchronize on the configuration lock?
        if (currentFilterChain.get() != null) {
            for (FilterContext context : currentFilterChain.get()) {
                context.destroy();
            }
        }
    }

    private PowerFilterChain getRequestFilterChain(MutableHttpServletResponse mutableHttpResponse, FilterChain chain) throws ServletException {
        PowerFilterChain requestFilterChain = null;
        try {
            boolean healthy = healthCheckService.isHealthy();
            List<FilterContext> filterChain = currentFilterChain.get();
            PowerFilterRouter router = powerFilterRouter.get();

            if (!healthy ||
                    filterChain == null ||
                    router == null) {
                LOG.warn("{}:{} -- Repose is not ready!", clusterId, nodeId);
                LOG.debug("{}:{} -- Health status: {}", clusterId, nodeId, healthy);
                LOG.debug("{}:{} -- Current filter chain: {}", clusterId, nodeId, filterChain);
                LOG.debug("{}:{} -- Power Filter Router: {}", clusterId, nodeId, router);

                mutableHttpResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Currently unable to serve requests");

                //Update the JMX bean with our status
                configurationInformation.updateNodeStatus(clusterId, nodeId, false);
            } else {
                requestFilterChain = new PowerFilterChain(filterChain, chain, router, metricsService);
            }
        } catch (PowerFilterChainException ex) {
            LOG.warn("{}:{} -- Error creating filter chain", clusterId, nodeId, ex);
            mutableHttpResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Error creating filter chain");
            mutableHttpResponse.setLastException(ex);

            //Update the JMX bean with our status
            configurationInformation.updateNodeStatus(clusterId, nodeId, false);
        }

        return requestFilterChain;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        final long startTime = System.currentTimeMillis();
        long streamLimit = containerConfigurationService.getContentBodyReadLimit();

        final MutableHttpServletRequest mutableHttpRequest = MutableHttpServletRequest.wrap((HttpServletRequest) request, streamLimit);
        final MutableHttpServletResponse mutableHttpResponse = MutableHttpServletResponse.wrap(mutableHttpRequest, (HttpServletResponse) response);

        try {
            new URI(mutableHttpRequest.getRequestURI());
            final PowerFilterChain requestFilterChain = getRequestFilterChain(mutableHttpResponse, chain);
            if (requestFilterChain != null) {
                requestFilterChain.startFilterChain(mutableHttpRequest, mutableHttpResponse);
            }
        } catch (URISyntaxException use) {
            LOG.debug("{}:{} -- Invalid URI requested: {}", clusterId, nodeId, mutableHttpRequest.getRequestURI(), use);
            mutableHttpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Error processing request");
            mutableHttpResponse.setLastException(use);
        } catch (Exception ex) {
            LOG.error("{}:{} -- Exception encountered while processing filter chain.", clusterId, nodeId, ex);
            mutableHttpResponse.sendError(HttpServletResponse.SC_BAD_GATEWAY, "Error processing request");
            mutableHttpResponse.setLastException(ex);
        } finally {
            // In the case where we pass/route the request, there is a chance that
            // the response will be committed by an underlying service, outside of repose
            if (!mutableHttpResponse.isCommitted()) {
                responseMessageService.handle(mutableHttpRequest, mutableHttpResponse);
                responseHeaderService.setVia(mutableHttpRequest, mutableHttpResponse);
            }

            try {
                mutableHttpResponse.writeHeadersToResponse();
                mutableHttpResponse.commitBufferToServletOutputStream();
            } catch (IOException ex) {
                LOG.error("{}:{} -- Error committing output stream", clusterId, nodeId, ex);
            }
            final long stopTime = System.currentTimeMillis();

            markResponseCodeHelper(mbcResponseCodes, ((HttpServletResponse) response).getStatus(), LOG, null);

            reportingService.incrementReposeStatusCodeCount(((HttpServletResponse) response).getStatus(), stopTime - startTime);
        }
    }

    public static void markResponseCodeHelper(MeterByCategory mbc, int responseCode, Logger log, String logPrefix) {
        if (mbc == null) {
            return;
        }

        int code = responseCode / 100;

        if (code == 2) {
            mbc.mark("2XX");
        } else if (code == 3) {
            mbc.mark("3XX");
        } else if (code == 4) {
            mbc.mark("4XX");
        } else if (code == 5) {
            mbc.mark("5XX");
        } else {
            log.error((logPrefix != null ? logPrefix + ":  " : "") + "Encountered invalid response code: " + responseCode);
        }
    }
}
