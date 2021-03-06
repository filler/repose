package org.openrepose.filters.derp

import javax.inject.Named
import javax.servlet._
import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import javax.ws.rs.core.MediaType

import com.rackspace.httpdelegation._
import com.typesafe.scalalogging.slf4j.LazyLogging

import scala.collection.JavaConverters._
import scala.util.{Failure, Success}

/**
 * The sole purpose of this filter is to reject any request with a header indicating that the request has been
 * delegated.
 *
 * This filter is header quality aware; the delegation header with the highest quality will be used to formulate a
 * response.
 */
@Named
class DerpFilter extends Filter with HttpDelegationManager with LazyLogging {

  override def init(filterConfig: FilterConfig): Unit = {
    logger.trace("DeRP filter initialized")
  }

  override def doFilter(servletRequest: ServletRequest, servletResponse: ServletResponse, filterChain: FilterChain): Unit = {
    val httpServletRequest = servletRequest.asInstanceOf[HttpServletRequest]
    val delegationValues = httpServletRequest.getHeaders(HttpDelegationHeaderNames.Delegated).asScala.toSeq

    if (delegationValues.isEmpty) {
      logger.debug("No delegation header present, forwarding the request")
      filterChain.doFilter(servletRequest, servletResponse)
    } else {
      val sortedErrors = parseDelegationValues(delegationValues).sortWith(_.quality > _.quality)
      val httpServletResponse = servletResponse.asInstanceOf[HttpServletResponse]

      sortedErrors match {
        case Seq() =>
          logger.warn("No delegation header could be parsed, returning a 500 response")
          sendError(httpServletResponse, 500, "Delegation header found but could not be parsed", MediaType.TEXT_PLAIN)
        case Seq(preferredValue, _*) =>
          logger.debug(s"Delegation header(s) present, returning a ${preferredValue.statusCode} response")
          sendError(httpServletResponse, preferredValue.statusCode, preferredValue.message, MediaType.TEXT_PLAIN)
      }
    }
  }

  override def destroy(): Unit = {
    logger.trace("DeRP filter destroyed")
  }

  def parseDelegationValues(delegationValues: Seq[String]): Seq[HttpDelegationHeader] = {
    delegationValues.flatMap { value =>
      parseDelegationHeader(value) match {
        case Success(delegationHeader) => Some(delegationHeader)
        case Failure(e) =>
          logger.warn("Failed to parse a delegation header: " + e.getMessage)
          None
      }
    }
  }

  def sendError(httpServletResponse: HttpServletResponse, statusCode: Int, responseBody: String, responseContentType: String): Unit = {
    httpServletResponse.setContentLength(responseBody.length)
    httpServletResponse.setContentType(MediaType.TEXT_PLAIN)
    httpServletResponse.getWriter.write(responseBody)
    httpServletResponse.sendError(statusCode)
  }
}
