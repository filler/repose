package org.openrepose.components.xsdvalidator.filter;

import com.rackspace.com.papi.components.checker.Config;
import com.rackspace.com.papi.components.checker.Validator;
import com.rackspace.com.papi.components.checker.handler.ServletResultHandler;
import com.rackspace.com.papi.components.checker.wadl.WADLException;
import com.rackspace.papi.commons.config.manager.UpdateListener;
import com.rackspace.papi.commons.config.parser.generic.GenericResourceConfigurationParser;
import com.rackspace.papi.commons.config.resource.ConfigurationResource;
import com.rackspace.papi.commons.util.StringUtilities;
import com.rackspace.papi.filter.logic.AbstractConfiguredFilterHandlerFactory;
import com.rackspace.papi.service.config.ConfigurationService;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import org.openrepose.components.xsdvalidator.servlet.config.ValidatorConfiguration;
import org.openrepose.components.xsdvalidator.servlet.config.ValidatorItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XsdValidatorHandlerFactory extends AbstractConfiguredFilterHandlerFactory<XsdValidatorHandler> {

    private static final Logger LOG = LoggerFactory.getLogger(XsdValidatorHandlerFactory.class);
    private ValidatorConfiguration validatorConfiguration;
    private ValidatorInfo defaultValidator;
    private Map<String, ValidatorInfo> validators;
    private boolean initialized = false;
    private final ConfigurationService manager;
    private final XsdValidatorWadlListener wadlListener;
    private final Object lock;
    private final String configRoot;

    public XsdValidatorHandlerFactory(ConfigurationService manager, String configurationRoot) {
        this.manager = manager;
        wadlListener = new XsdValidatorWadlListener();
        lock = new Object();
        this.configRoot = configurationRoot;
    }


    private void unsubscribeAll() {
        synchronized (lock) {
            initialized = false;
            if (validators == null) {
                return;
            }

            for (ValidatorInfo info : validators.values()) {
                manager.unsubscribeFrom(info.getUri(), wadlListener);
            }
        }

    }

    private class XsdValidatorWadlListener implements UpdateListener<ConfigurationResource> {

        private String getNormalizedPath(String uri) {
            String path = uri;
            try {
                path = new URL(uri).toString();
            } catch (MalformedURLException ex) {
                LOG.warn("Invalid URL: " + uri);
            }
            return path;
        }

        @Override
        public void configurationUpdated(ConfigurationResource config) {
            LOG.info("WADL file changed: " + config.name());
            synchronized (lock) {
                if (validators == null) {
                    return;
                }
                boolean found = false;

                for (ValidatorInfo info : validators.values()) {
                    if (getNormalizedPath(info.getUri()).equals(config.name())) {
                        info.clearValidator();
                        found = true;
                    }
                }

                if (!found) {
                    // If we couldn't match the particular config... be safe and clear 
                    // all fo the validators
                    for (ValidatorInfo info : validators.values()) {
                        info.clearValidator();
                    }
                }
            }
        }
    }

    private void addListener(String wadl) {
        LOG.info("Watching WADL: " + wadl);
        manager.subscribeTo(wadl, wadlListener, new GenericResourceConfigurationParser());
    }
    
    private String getWadlPath(String wadl) {
        return !wadl.contains("://")? StringUtilities.join("file://", configRoot, "/", wadl): wadl;
    }

    private void initialize() {
        synchronized (lock) {
            if (initialized || validatorConfiguration == null) {
                return;
            }

            validators = new HashMap<String, ValidatorInfo>();
            defaultValidator = null;

            for (ValidatorItem validatorItem : validatorConfiguration.getValidator()) {
                Config config = new Config();
                config.setResultHandler(new ServletResultHandler());
                config.setUseSaxonEEValidation(validatorItem.isUseSaxon());
                config.setCheckWellFormed(validatorItem.isCheckWellFormed());
                config.setCheckXSDGrammar(validatorItem.isCheckXsdGrammer());
                config.setCheckElements(validatorItem.isCheckElements());
                config.setXPathVersion(validatorItem.getXpathVersion());
                
                ValidatorInfo validator = new ValidatorInfo(validatorItem.getRole(), getWadlPath(validatorItem.getWadl()), config);
                validators.put(validatorItem.getRole(), validator);
                if (validatorItem.isDefault()) {
                    defaultValidator = validator;
                }
                addListener(validator.getUri());
            }

            initialized = true;
        }
    }

    private class XsdValidationConfigurationListener implements UpdateListener<ValidatorConfiguration> {

        @Override
        public void configurationUpdated(ValidatorConfiguration configurationObject) {
            validatorConfiguration = configurationObject;
            unsubscribeAll();
        }
    }

    @Override
    protected XsdValidatorHandler buildHandler() {
        initialize();
        return new XsdValidatorHandler(defaultValidator, validators);
    }

    @Override
    protected Map<Class, UpdateListener<?>> getListeners() {
        final Map<Class, UpdateListener<?>> updateListeners = new HashMap<Class, UpdateListener<?>>();
        updateListeners.put(ValidatorConfiguration.class, new XsdValidationConfigurationListener());
        return updateListeners;
    }
}
