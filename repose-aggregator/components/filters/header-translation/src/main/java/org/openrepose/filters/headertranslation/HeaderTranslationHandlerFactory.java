package org.openrepose.filters.headertranslation;

import org.openrepose.filters.headertranslation.config.Header;
import org.openrepose.filters.headertranslation.config.HeaderTranslationType;
import org.openrepose.commons.config.manager.UpdateListener;
import org.openrepose.core.filter.logic.AbstractConfiguredFilterHandlerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HeaderTranslationHandlerFactory extends AbstractConfiguredFilterHandlerFactory<HeaderTranslationHandler> {

    private List<Header> sourceHeaders;

    protected HeaderTranslationHandlerFactory() {
        sourceHeaders = new ArrayList<Header>();
    }

    @Override
    protected HeaderTranslationHandler buildHandler() {
        if (!this.isInitialized()) {
            return null;
        }
        return new HeaderTranslationHandler(sourceHeaders);
    }

    @Override
    protected Map<Class, UpdateListener<?>> getListeners() {
        return new HashMap<Class, UpdateListener<?>>() {
            {
                put(HeaderTranslationType.class, new HeaderTranslationConfigurationListener());
            }
        };
    }

    private class HeaderTranslationConfigurationListener implements UpdateListener<HeaderTranslationType> {

        private boolean isInitialized = false;

        @Override
        public void configurationUpdated(HeaderTranslationType headerTranslationTypeConfigObject) {
            sourceHeaders = headerTranslationTypeConfigObject.getHeader();
            isInitialized = true;
        }

        @Override
        public boolean isInitialized() {
            return isInitialized;
        }
    }
}
