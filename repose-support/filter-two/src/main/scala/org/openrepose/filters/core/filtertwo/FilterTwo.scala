package org.openrepose.filters.core.filtertwo

import javax.inject.Named
import javax.servlet._
import javax.servlet.http.HttpServletRequest


/**
  * Created by dimi5963 on 1/6/15.
  */
@Named
class FilterTwo extends Filter {
   override def init(p1: FilterConfig): Unit = {
     //Meh?
   }

   override def doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain): Unit = {
     val r: HttpServletRequest = request.asInstanceOf[HttpServletRequest]
     if(r.getHeader("FOO") != null && !r.getHeader("FOO").equals("BAR")){
       throw new IllegalArgumentException("this ain't right!")
     }
     chain.doFilter(r, response)
   }

   override def destroy(): Unit = {

   }
 }

