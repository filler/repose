package org.openrepose.filters.second

import javax.inject.Named
import javax.servlet._

/**
 * This test filter assumes it is operating in the test classpath of core unit tests
 */
@Named
class SecondFilter extends Filter {
  override def init(p1: FilterConfig): Unit = {
    //Meh?
  }

  override def doFilter(p1: ServletRequest, p2: ServletResponse, p3: FilterChain): Unit = {

  }

  override def destroy(): Unit = {

  }
}
