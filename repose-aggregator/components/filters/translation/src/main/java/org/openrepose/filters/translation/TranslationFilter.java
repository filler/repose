package org.openrepose.filters.translation;

import org.openrepose.core.filter.FilterConfigHelper;
import org.openrepose.core.filter.logic.impl.FilterLogicHandlerDelegate;
import org.openrepose.core.services.config.ConfigurationService;
import org.openrepose.core.spring.ReposeSpringProperties;
import org.openrepose.filters.translation.config.TranslationConfig;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Value;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.*;
import java.io.IOException;
import java.net.URL;

@Named
public class TranslationFilter implements Filter {

    private static final Logger LOG = org.slf4j.LoggerFactory.getLogger(TranslationFilter.class);
    private static final String DEFAULT_CONFIG = "translation.cfg.xml";
    private String config;
    private TranslationHandlerFactory handlerFactory;
    private final ConfigurationService configurationService;
    private String configurationRoot;

    @Inject
    public TranslationFilter(ConfigurationService configurationService,
                             @Value(ReposeSpringProperties.CORE.CONFIG_ROOT)String configurationRoot) {
        this.configurationService = configurationService;
        this.configurationRoot = configurationRoot;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        new FilterLogicHandlerDelegate(request, response, chain).doFilter(handlerFactory.newHandler());
    }

    @Override
    public void destroy() {
        configurationService.unsubscribeFrom(config, handlerFactory);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        config = new FilterConfigHelper(filterConfig).getFilterConfig(DEFAULT_CONFIG);
        LOG.info("Initializing filter using config " + config);
        handlerFactory = new TranslationHandlerFactory(configurationService, configurationRoot, config);
        URL xsdURL = getClass().getResource("/META-INF/schema/config/translation-configuration.xsd");
        this.configurationService.subscribeTo(filterConfig.getFilterName(), config, xsdURL, handlerFactory, TranslationConfig.class);
    }
}
