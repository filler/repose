package com.rackspace.papi.filter;

import com.rackspace.papi.domain.ReposeInstanceInfo;
import com.rackspace.papi.model.Node;
import com.rackspace.papi.model.ReposeCluster;
import com.rackspace.papi.service.context.ServletContextHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Scope;
import javax.inject.Named;

import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import java.util.List;

/**
 *
 * @author zinic
 */
@Named("powerFilterChainBuilder")
@Scope("prototype")
public class PowerFilterChainBuilderImpl implements PowerFilterChainBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(PowerFilterChainBuilderImpl.class);
    private final PowerFilterRouter router;
    private List<FilterContext> currentFilterChain;
    private ReposeCluster domain;
    private Node localhost;
    private ReposeInstanceInfo instanceInfo;
    private ServletContext servletContext;

    @Inject
    public PowerFilterChainBuilderImpl(@Qualifier("powerFilterRouter") PowerFilterRouter router, @Qualifier("reposeInstanceInfo") ReposeInstanceInfo instanceInfo) {
        Thread.currentThread().setName(instanceInfo.toString());
        LOG.info("Creating filter chain builder");
        this.router = router;
        this.instanceInfo = instanceInfo;
    }

    @Override
    public void initialize(ReposeCluster domain, Node localhost, List<FilterContext> currentFilterChain, ServletContext servletContext, String defaultDst) throws PowerFilterChainException {
        LOG.info("Initializing filter chain builder");
        this.currentFilterChain = currentFilterChain;
        this.domain = domain;
        this.localhost = localhost;
        this.servletContext = servletContext;
        this.router.initialize(domain, localhost, servletContext, defaultDst);
    }


    @Override
    public PowerFilterChain newPowerFilterChain(FilterChain containerFilterChain) throws PowerFilterChainException {
        if (router == null) {
            throw new PowerFilterChainException("Power Filter Router has not been initialized yet.");
        }
        return new PowerFilterChain(currentFilterChain, containerFilterChain, router, instanceInfo,
                                    ServletContextHelper.getInstance(servletContext).getPowerApiContext().metricsService());
    }

    @Override
    public ReposeCluster getReposeCluster() {
        return domain;
    }

    @Override
    public Node getLocalhost() {
        return localhost;
    }

    @Override
    public void destroy() {
        for (FilterContext context : currentFilterChain) {
            context.destroy();
        }
    }
}
