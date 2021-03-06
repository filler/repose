package org.openrepose.commons.config.parser.jaxb;

import org.apache.commons.pool.ObjectPool;
import org.apache.commons.pool.impl.SoftReferenceObjectPool;
import org.openrepose.commons.config.parser.common.AbstractConfigurationObjectParser;
import org.openrepose.commons.config.resource.ConfigurationResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.net.URL;

/**
 * Contains a {@link org.apache.commons.pool.PoolableObjectFactory Pool} of {@link org.openrepose.commons.config.parser.jaxb.UnmarshallerValidator
 * UnmarshallerValidator} which can be used to unmmarshal JAXB XML for a given type T.
 *
 * @param <T> The configuration class which is unmarshalled
 */
public class JaxbConfigurationParser<T> extends AbstractConfigurationObjectParser<T> {

    private static final Logger LOG = LoggerFactory.getLogger(JaxbConfigurationParser.class);
    private final ObjectPool<UnmarshallerValidator> objectPool;

    public JaxbConfigurationParser(Class<T> configurationClass, JAXBContext jaxbContext, URL xsdStreamSource) {
        super(configurationClass);
        objectPool = new SoftReferenceObjectPool<>(new UnmarshallerPoolableObjectFactory(jaxbContext, xsdStreamSource, configurationClass.getClassLoader()));
    }

    /**
     * Creates a jaxb parser for a specific classloader.
     * Throws up the JAXB exception so that things know they have to handle it.
     * Moved from a "factory" class that was just a collection of static methods
     *
     * @param configurationClass
     * @param xsdStreamSource
     * @param loader
     * @param <T>
     * @return
     * @throws javax.xml.bind.JAXBException
     */
    public static <T> JaxbConfigurationParser<T> getXmlConfigurationParser(Class<T> configurationClass, URL xsdStreamSource, ClassLoader loader) throws JAXBException {
        if(xsdStreamSource == null) {
            LOG.warn("Creating a JAXB Parser Pool without any schema to validate for {}", configurationClass);
            if(LOG.isDebugEnabled()) {
                Exception tracer = new Exception("Repose Devs might care about this trace");
                LOG.debug("Logging the current stack to find where a parser pool is created without a validator", tracer);
            }
        }
        final JAXBContext context = JAXBContext.newInstance(configurationClass.getPackage().getName(), loader);
        return new JaxbConfigurationParser<>(configurationClass, context, xsdStreamSource);
    }

    @Override
    public T read(ConfigurationResource cr) {
        Object rtn = null;
        UnmarshallerValidator pooledObject;
        try {
            pooledObject = objectPool.borrowObject();
            try {
                final Object unmarshalledObject = pooledObject.validateUnmarshal(cr.newInputStream());
                if (unmarshalledObject instanceof JAXBElement) {
                    rtn = ((JAXBElement) unmarshalledObject).getValue();
                } else {
                    rtn = unmarshalledObject;
                }
            } catch (IOException ioe) {
                objectPool.invalidateObject(pooledObject);
                pooledObject = null;
                LOG.warn("This *MIGHT* be important! Unable to read configuration file: {}", ioe.getMessage());
                LOG.trace("Unable to read configuration file.", ioe);
            } catch (Exception e) {
                objectPool.invalidateObject(pooledObject);
                pooledObject = null;
                LOG.error("Failed to utilize the UnmarshallerValidator. Reason: {}", e.getLocalizedMessage());
                LOG.trace("", e);
            } finally {
                if (pooledObject != null) {
                    objectPool.returnObject(pooledObject);
                }
            }
        } catch (Exception e) {
            LOG.error("Failed to obtain an UnmarshallerValidator. Reason: {}", e.getLocalizedMessage());
            LOG.trace("", e);
        }
        if (!configurationClass().isInstance(rtn)) {
            throw new ClassCastException("Parsed object from XML does not match the expected configuration class. "
                    + "Expected: " + configurationClass().getCanonicalName() + "  -  "
                    + "Actual: " + (rtn == null ? null : rtn.getClass().getCanonicalName()));
        }
        return configurationClass().cast(rtn);
    }
}
