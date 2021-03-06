package org.openrepose.filters.translation;

import org.openrepose.commons.config.manager.UpdateListener;
import org.openrepose.commons.config.parser.generic.GenericResourceConfigurationParser;
import org.openrepose.commons.config.resource.ConfigurationResource;
import org.openrepose.commons.utils.StringUtilities;
import org.openrepose.core.services.config.ConfigurationService;

import java.util.HashSet;
import java.util.Set;

public class XslUpdateListener implements UpdateListener<ConfigurationResource> {

    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(XslUpdateListener.class);
    private final TranslationHandlerFactory handlerFactory;
    private final ConfigurationService configurationService;
    private final Set<String> watchList;
    private final String configRoot;
    private boolean isInitialized = false;

    public XslUpdateListener(TranslationHandlerFactory handlerFactory, ConfigurationService configurationService, String configRoot) {
        this.handlerFactory = handlerFactory;
        this.configurationService = configurationService;
        this.watchList = new HashSet<String>();
        this.configRoot = configRoot;
    }

    private String getAbsolutePath(String xslPath) {
        return !xslPath.contains("://") ? StringUtilities.join("file://", configRoot, "/", xslPath) : xslPath;
    }

    public void addToWatchList(String path) {
        watchList.add(getAbsolutePath(path));
    }

    public void listen() {
        for (String xsl : watchList) {
            LOG.info("Watching XSL: " + xsl);
            configurationService.subscribeTo("translation", xsl, this, new GenericResourceConfigurationParser(), false);
        }
    }

    public void unsubscribe() {
        for (String xsl : watchList) {
            configurationService.unsubscribeFrom(xsl, this);
        }

        watchList.clear();
    }

    @Override
    public void configurationUpdated(ConfigurationResource config) {
        LOG.info("XSL file changed: " + config.name());
        handlerFactory.buildProcessorPools();
        isInitialized = true;
    }

    @Override
    public boolean isInitialized() {
        return isInitialized;
    }
  
}
