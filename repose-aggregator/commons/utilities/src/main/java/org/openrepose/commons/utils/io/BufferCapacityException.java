package org.openrepose.commons.utils.io;

import java.io.IOException;

/**
 *
 * @author zinic
 */
public class BufferCapacityException extends IOException {

   public BufferCapacityException(String string, Throwable thrwbl) {
      super(string, thrwbl);
   }

   public BufferCapacityException(String string) {
      super(string);
   }
}
