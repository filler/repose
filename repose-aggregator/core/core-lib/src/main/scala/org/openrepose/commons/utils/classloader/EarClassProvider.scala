package org.openrepose.commons.utils.classloader

import java.io.{File, FileInputStream, FileOutputStream, IOException}
import java.net.{URL, URLClassLoader}
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.{FileVisitResult, Files, Path, SimpleFileVisitor}
import java.util.UUID
import java.util.zip.{ZipFile, ZipInputStream}
import javax.xml.bind.JAXBContext

import com.oracle.javaee6.{ApplicationType, FilterType, ObjectFactory, WebFragmentType}
import org.openrepose.commons.config.parser.jaxb.JaxbConfigurationParser
import org.openrepose.commons.config.resource.impl.BufferedURLConfigurationResource
import org.slf4j.LoggerFactory

import scala.collection.mutable

object EarClassProvider {
  //Need a static singleton for the entire JVM for the JAXB Context
  val jaxbContext = JAXBContext.newInstance(classOf[ObjectFactory])
}

class EarClassProvider(earFile: File, unpackRoot: File) {
  val log = LoggerFactory.getLogger(classOf[EarClassProvider])

  val outputDir = new File(unpackRoot, UUID.randomUUID().toString)

  private def unpack(): Unit = {
    try {
      if (!outputDir.exists()) {
        outputDir.mkdir()
      }

      //Make sure it's actually a zip file, so we can fail with some kind of exception
      new ZipFile(earFile)

      val zis = new ZipInputStream(new FileInputStream(earFile))

      val buffer = new Array[Byte](1024)
      Stream.continually(zis.getNextEntry).
        takeWhile(_ != null).foreach(entry =>
        //Unpack the entry
        if (entry.isDirectory) {
          new File(outputDir, entry.getName).mkdir()
        } else {
          val outFile = new File(outputDir, entry.getName)
          val ofs = new FileOutputStream(outFile)
          Stream.continually(zis.read(buffer)).takeWhile(_ != -1).foreach(count => ofs.write(buffer, 0, count))
          ofs.close()
        }
        )
      zis.close()
    } catch {
      case e: Exception =>
        log.warn("Error during ear extraction! Partial extraction at {}", outputDir.getAbsolutePath)
        throw new EarProcessingException("Unable to fully extract file", e);
    }
  }

  @throws(classOf[EarProcessingException])
  def getClassLoader(): ClassLoader = {
    computeClassLoader
  }
  
  /**
   * Calls unpack, and gets you a new classloader for all the items in this ear file
   */
  private lazy val computeClassLoader: ClassLoader = {
    unpack()

    val mutableList = mutable.MutableList[Path]()

    Files.walkFileTree(outputDir.toPath(), new SimpleFileVisitor[Path] {
      override def visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult = {
        if (file.toString.endsWith(".jar")) {
          mutableList += file
        }
        super.visitFile(file, attrs)
      }

      override def postVisitDirectory(dir: Path, exc: IOException): FileVisitResult = {
        mutableList += dir
        super.postVisitDirectory(dir, exc)
      }
    })

    val fileUrls: Array[URL] = mutableList.map { path =>
      path.toUri.toURL
    }.toArray

    //Spring needs the parent classloader to find the annotations when in tomcat.
    //Since it works for both valve and the war deployments, we will give it the parent classloader for both.
    URLClassLoader.newInstance(fileUrls, this.getClass.getClassLoader)
  }

  @throws(classOf[EarProcessingException])
  def getEarDescriptor():EarDescriptor = {
    computeEarDescriptor
  }

  private lazy val computeEarDescriptor: EarDescriptor = {
    import org.openrepose.commons.utils.classloader.EarClassProvider.jaxbContext

    val applicationXmlUrl = computeClassLoader.getResource("META-INF/application.xml")
    val appXmlParser = new JaxbConfigurationParser[ApplicationType](classOf[ApplicationType], jaxbContext, null)
    val appXml = appXmlParser.read(new BufferedURLConfigurationResource(applicationXmlUrl))

    val optionName = for {
      a <- Option(appXml)
      name <- Option(a.getApplicationName)
      value <- Option(name.getValue) if !value.trim.isEmpty
    } yield {
      value
    }
    val appName = optionName getOrElse (throw new EarProcessingException(s"Unable to parse Application Name from ear file ${earFile.getName}!"))

    //Load the WebFragment data out of the ear file
    val webFragmentUrl = computeClassLoader.getResource("WEB-INF/web-fragment.xml")
    val webFragmentParser = new JaxbConfigurationParser[WebFragmentType](classOf[WebFragmentType], jaxbContext, null)
    val webFragment = webFragmentParser.read(new BufferedURLConfigurationResource(webFragmentUrl))

    import scala.collection.JavaConversions._

    //http://stackoverflow.com/a/4719732/423218
    //The .toSeq in here is to be able to get the for comprehension to properly create map/flatmap calls
    val filterMap:Map[String, FilterType] = (
      for{
        fragment <- Option(webFragment).toSeq
        elementCollection <- Option(fragment.getNameOrDescriptionAndDisplayName).toSeq
        element <- elementCollection if element.getDeclaredType.equals(classOf[FilterType])
        filterType = element.getValue.asInstanceOf[FilterType]
        filterNameType <- Option(filterType.getFilterName) if Option(filterType.getFilterClass).isDefined
        filterName <- Option(filterNameType.getValue)
      } yield {
        filterName -> filterType
      }
      ).toMap

    if(filterMap.isEmpty) {
      throw new EarProcessingException(s"There aren't any usable filters in ${earFile.getName}! Check your web-fragment!")
    }

    new EarDescriptor(appName, filterMap)
  }
}
