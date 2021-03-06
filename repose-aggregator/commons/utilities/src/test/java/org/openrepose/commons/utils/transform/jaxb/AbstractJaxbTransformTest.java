package org.openrepose.commons.utils.transform.jaxb;

import org.apache.commons.pool.ObjectPool;
import org.openrepose.commons.utils.pooling.ResourceConstructionException;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by IntelliJ IDEA.
 * User: joshualockwood
 * Date: Apr 25, 2011
 * Time: 6:03:36 PM
 */
@RunWith(Enclosed.class)
public class AbstractJaxbTransformTest {
    public static class WhenCreatingNewInstances {
        private AbstractJaxbTransform jaxbTransform;
        private JAXBContext jaxbContext;

        @Before
        public void setup() {
            jaxbContext = mock(JAXBContext.class);

            jaxbTransform = new SampleJaxbTransform(jaxbContext);
        }

        @Test
        public void shouldReturnNonNullForMarshallerPool() {
            assertNotNull(jaxbTransform.getMarshallerPool());
        }

        @Test(expected=ResourceConstructionException.class)
        public void shouldThrowExceptionIfCanNotCreateMarshallerPool() throws Exception {
            when(jaxbContext.createMarshaller()).thenThrow(new JAXBException("test"));

            jaxbTransform.getMarshallerPool().borrowObject();
        }

        @Test
        public void shouldReturnNonNullForUnmarshallerPool() {
            assertNotNull(jaxbTransform.getUnmarshallerPool());
        }

        @Test(expected=ResourceConstructionException.class)
        public void shouldThrowExceptionIfCanNotCreateUnmarshallerPool() throws Exception {
            when(jaxbContext.createUnmarshaller()).thenThrow(new JAXBException("test"));

            jaxbTransform.getUnmarshallerPool().borrowObject();
        }
    }

    static class SampleJaxbTransform extends AbstractJaxbTransform {
        public SampleJaxbTransform(JAXBContext ctx) {
            super(ctx);
        }
    }
}
