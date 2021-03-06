package org.openrepose.core.services.config;

import org.openrepose.commons.config.manager.UpdateListener;
import org.openrepose.commons.config.parser.common.ConfigurationParser;
import org.openrepose.commons.config.resource.ConfigurationResourceResolver;
import org.openrepose.commons.utils.Destroyable;

import java.net.URL;

public interface ConfigurationService extends Destroyable {
    ConfigurationResourceResolver getResourceResolver();

    <T> void subscribeTo(String configurationName, UpdateListener<T> listener, Class<T> configurationClass);

    <T> void subscribeTo(String filterName, String configurationName, UpdateListener<T> listener, Class<T> configurationClass);

    <T> void subscribeTo(String configurationName, URL xsdStreamSource, UpdateListener<T> listener, Class<T> configurationClass);

    <T> void subscribeTo(String filterName, String configurationName, URL xsdStreamSource, UpdateListener<T> listener, Class<T> configurationClass);

    <T> void subscribeTo(String filterName, String configurationName, UpdateListener<T> listener, ConfigurationParser<T> customParser);

    <T> void subscribeTo(String filterName, String configurationName, UpdateListener<T> listener, ConfigurationParser<T> customParser, boolean sendNotificationNow);

    void unsubscribeFrom(String configurationName, UpdateListener plistener);
}
