package org.openrepose.filters.urinormalization;

import org.openrepose.commons.config.manager.UpdateListener;
import org.openrepose.commons.utils.http.normal.QueryStringNormalizer;
import org.openrepose.core.filter.logic.AbstractConfiguredFilterHandlerFactory;
import org.openrepose.core.services.reporting.metrics.MetricsService;
import org.openrepose.filters.urinormalization.config.HttpMethod;
import org.openrepose.filters.urinormalization.config.Target;
import org.openrepose.filters.urinormalization.config.UriFilterList;
import org.openrepose.filters.urinormalization.config.UriNormalizationConfig;
import org.openrepose.filters.urinormalization.normalizer.MediaTypeNormalizer;
import org.openrepose.filters.urinormalization.normalizer.MultiInstanceWhiteListFactory;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class UriNormalizationHandlerFactory extends AbstractConfiguredFilterHandlerFactory<UriNormalizationHandler> {
    private final MetricsService metricsService;
    private Collection<QueryParameterNormalizer> queryStringNormalizers;
    private MediaTypeNormalizer mediaTypeNormalizer;

    public UriNormalizationHandlerFactory(MetricsService metricsService) {
        this.metricsService = metricsService;
    }

    private class UriNormalizationConfigurationListener implements UpdateListener<UriNormalizationConfig> {
        private boolean isInitialized = false;

        @Override
        public void configurationUpdated(UriNormalizationConfig configurationObject) {
            final UriFilterList uriFilterList = configurationObject.getUriFilters();
            final Map<String, QueryParameterNormalizer> newNormalizers = new HashMap<String, QueryParameterNormalizer>();

            if (uriFilterList != null) {
                for (Target target : uriFilterList.getTarget()) {
                    boolean alphabetize = target.isAlphabetize();
                    final MultiInstanceWhiteListFactory whiteListFactory = new MultiInstanceWhiteListFactory(target.getWhitelist());
                    final QueryStringNormalizer normalizerInstance = new QueryStringNormalizer(whiteListFactory, alphabetize);
                    if (target.getHttpMethods().isEmpty()) {
                        target.getHttpMethods().add(HttpMethod.ALL);
                    }
                    for (HttpMethod method : target.getHttpMethods()) {
                        QueryParameterNormalizer methodScopedNormalizer = newNormalizers.get(method.name());

                        if (methodScopedNormalizer == null) {
                            methodScopedNormalizer = new QueryParameterNormalizer(method);
                            newNormalizers.put(method.name(), methodScopedNormalizer);
                        }

                        methodScopedNormalizer.getUriSelector().addPattern(target.getUriRegex(), normalizerInstance);
                    }
                }
            }

            queryStringNormalizers = newNormalizers.values();
            if (configurationObject.getMediaVariants() != null) {
                mediaTypeNormalizer = new MediaTypeNormalizer(configurationObject.getMediaVariants().getMediaType());
            }
            isInitialized = true;
        }

        @Override
        public boolean isInitialized() {
            return isInitialized;
        }
    }

    @Override
    protected Map<Class, UpdateListener<?>> getListeners() {
        final Map<Class, UpdateListener<?>> listenerMap = new HashMap<Class, UpdateListener<?>>();
        listenerMap.put(UriNormalizationConfig.class, new UriNormalizationConfigurationListener());

        return listenerMap;
    }

    @Override
    protected UriNormalizationHandler buildHandler() {
        if (!this.isInitialized()) {
            return null;
        }

        return new UriNormalizationHandler(queryStringNormalizers, mediaTypeNormalizer, metricsService);

    }
}
