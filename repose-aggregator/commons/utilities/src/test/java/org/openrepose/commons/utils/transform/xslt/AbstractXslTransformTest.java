package org.openrepose.commons.utils.transform.xslt;

import org.apache.commons.pool.ObjectPool;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;

import javax.xml.transform.Templates;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by IntelliJ IDEA.
 * User: joshualockwood
 * Date: Apr 25, 2011
 * Time: 4:47:47 PM
 */
@RunWith(Enclosed.class)
public class AbstractXslTransformTest {
    public static class WhenCreatingNewInstances {
        private AbstractXslTransform xslTransform;
        private Templates templates;

        @Before
        public void setup() {
            templates = mock(Templates.class);

            xslTransform = new SampleXslTransform(templates);
        }

        @Test
        public void shouldReturnNonNullForTransformerPool() {
            ObjectPool<Transformer> transformerPool;

            transformerPool = xslTransform.getXslTransformerPool();

            assertNotNull(transformerPool);
        }

        @Test
        public void shouldReturnPoolWithDefaultMinSizeOfOne() throws Exception {
            when(templates.newTransformer())
                    .thenReturn(mock(Transformer.class));

            Integer expected, actual;

            ObjectPool<Transformer> transformerPool;

            expected = 1;

            transformerPool = xslTransform.getXslTransformerPool();
            final Transformer pooledObject = transformerPool.borrowObject();

            actual = transformerPool.getNumActive() + transformerPool.getNumIdle();

            if(pooledObject != null) {
                transformerPool.returnObject(pooledObject);
            }

            assertEquals(expected, actual);
        }

        @Test(expected=XsltTransformationException.class)
        public void shouldThrowExceptionIfXslTransformerCanNotBeGenerated() throws Exception {
            when(templates.newTransformer())
                    .thenThrow(new TransformerConfigurationException());

            //TODO: review...is it possible that too much is being done during construction?
            new SampleXslTransform(templates).getXslTransformerPool().borrowObject();
        }
    }

    static class SampleXslTransform extends AbstractXslTransform {
        public SampleXslTransform(Templates _transformationTemplates) {
            super(_transformationTemplates);
        }
    }
}
