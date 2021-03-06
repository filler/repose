package org.openrepose.valve.spring

import java.net.{InetAddress, NetworkInterface, UnknownHostException}
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import javax.inject.{Inject, Named}

import com.typesafe.scalalogging.slf4j.LazyLogging
import org.openrepose.commons.config.manager.UpdateListener
import org.openrepose.core.container.config.ContainerConfiguration
import org.openrepose.core.services.config.ConfigurationService
import org.openrepose.core.systemmodel.SystemModel
import org.openrepose.valve.ReposeJettyServer
import org.springframework.beans.factory.DisposableBean

import scala.util.{Try, Failure, Success}


/**
 * A singleton that's spring aware because of the services it needs to use.
 */
@Named
class ValveRunner @Inject()(
                                configService: ConfigurationService
                                ) extends DisposableBean with LazyLogging {

  private val systemModelXsdURL = getClass.getResource("/META-INF/schema/system-model/system-model.xsd")
  private val containerXsdUrl = getClass.getResource("/META-INF/schema/container/container-configuration.xsd")

  //Just a single countdown latch that gets triggered when told to stop
  private val runLatch = new CountDownLatch(1)

  private var activeNodes = Set[ReposeJettyServer]()
  private val nodeModificationLock = new Object()

  private val currentContainerConfig = new AtomicReference[ContainerConfiguration]()
  private val currentSystemModel = new AtomicReference[SystemModel]()

  // Note this won't pick up on interfaces added after repose has been turned on I think (oh well?)
  private val localAddresses: Set[InetAddress] = {
    import scala.collection.JavaConverters._
    NetworkInterface.getNetworkInterfaces.asScala.toList.flatMap(interface =>
      interface.getInetAddresses.asScala.toList).toSet
  }

  def getActiveNodes: Set[ReposeJettyServer] = {
    nodeModificationLock.synchronized {
      Set.empty[ReposeJettyServer] ++ activeNodes
    }
  }

  /**
   * This method should block, so that way the primary java method doesn't quit
   * @return
   */
  def run(configRoot: String, insecure: Boolean): Int = {
    //Putting the config listeners in here, because I want the context for the configRoot, and the Insecure string

    def updateNodes(): Unit = {
      logger.debug("Updating nodes!")
      val systemModel = currentSystemModel.get
      val containerConfig = currentContainerConfig.get

      if (Option(systemModel).isDefined && Option(containerConfig).isDefined) {
        val sslConfig = containerConfig.getDeploymentConfig.getSslConfiguration

        def isLocal(host: String): Boolean = {
          try {
            localAddresses.contains(InetAddress.getByName(host))
          } catch {
            case e: UnknownHostException => false
          }
        }

        //Because it's so much easier to have all this in one object rather than having to get it from a hierarchy
        case class ConfiguredNode(clusterId: String, nodeId: String, host: String, httpPort: Option[Int], httpsPort: Option[Int])

        import scala.collection.JavaConversions._
        //Figure out what nodes are new in the system model, and do things
        //Get a list of ConfiguredNodes (so I have all the information I need) from the XML object by mapping the heck out of the
        //ugly jaxb objects
        val newConfiguredLocalNodes = systemModel.getReposeCluster.toList.flatMap { cluster =>
          cluster.getNodes.getNode.toList.filter(node => isLocal(node.getHostname)).map { xmlNode =>
            //This is a wrapper function to go from the XSD's primitive int type to an Option, so that it has meaning
            val intToOption: Int => Option[Int] = { i =>
              if (i == 0) {
                None
              } else {
                Some(i)
              }
            }
            ConfiguredNode(cluster.getId,
              xmlNode.getId,
              xmlNode.getHostname,
              intToOption(xmlNode.getHttpPort),
              intToOption(xmlNode.getHttpsPort))
          }
        }

        //If there are no configured local nodes, we're going to bail on all of it
        if (newConfiguredLocalNodes.isEmpty) {
          logger.error("No local nodes found in system-model, exiting Valve!")
          runLatch.countDown()
        } else {
          //TODO: replace this with a thread that loops and uses the LinkedBlockingQueue to handle messages...
          //TODO: would also have to handle an exit state
          //Grab ahold of the node lock, so that no other thread dorks with our nodes while we are
          nodeModificationLock.synchronized {
            //Build a list of nodes that we're going to stop
            //This list is things that are in the active list, but not in the newly parsed list.
            val stopList = activeNodes.filterNot { activeNode =>
              newConfiguredLocalNodes.exists { node =>
                node.nodeId == activeNode.nodeId &&
                  node.clusterId == activeNode.clusterId &&
                  node.httpPort == activeNode.httpPort &&
                  node.httpsPort == activeNode.httpsPort
              }
            }

            //Get things that aren't in the active nodes list, but are in the new configured nodes list
            //These we're going to start up
            val startList = newConfiguredLocalNodes.filterNot { n =>
              activeNodes.exists { active =>
                active.nodeId == n.nodeId &&
                  active.clusterId == n.clusterId &&
                  active.httpPort == n.httpPort &&
                  active.httpsPort == n.httpsPort
              }
            }

            //The combination of these two lists will also duplicate nodes, so that a node will be restarted with
            //different settings!

            logger.debug({
              "New configured nodes: " +
                newConfiguredLocalNodes.map { node => s"${node.clusterId}:${node.nodeId}:${node.httpPort}:${node.httpsPort}"}
            })

            logger.debug({
              " Nodes to stop: " +
                stopList.map { node => s"${node.clusterId}:${node.nodeId}:${node.httpPort}:${node.httpsPort}"}
            })

            logger.debug({
              "Nodes to start: " +
                startList.map { node => s"${node.clusterId}:${node.nodeId}:${node.httpPort}:${node.httpsPort}"}

            })

            //Shutdown all the stop nodes
            activeNodes = activeNodes -- stopList //Take out all the nodes that we're going to stop
            stopList.foreach { node =>
              node.shutdown()
            }


            //Start up all the new nodes, replacing the existing nodes list with a new one
            activeNodes = activeNodes ++ startList.flatMap { n =>
              val node = new ReposeJettyServer(n.clusterId, n.nodeId, n.httpPort, n.httpsPort, Option(sslConfig))
              try{
                node.start()
                Some(node)
              } catch {
                case e:Exception => {
                  //If we couldn't start a node, throw a fatal error, and try to start other nodes?
                  // at the very least, we need to unload all the things, because it's buggered.
                  node.shutdown()
                  logger.error(s"Unable to start repose node ${node.clusterId}:${node.nodeId} !!!!", e)
                  None
                }
              }
            }

            //Do a quick sanity check, in case all local nodes are broke
            if(activeNodes.isEmpty) {
              logger.error("Unable to start up *any* local nodes, exiting valve, because there's nothing to do!")
              runLatch.countDown()
            }

            logger.debug({
              "Current running nodes: " +
                activeNodes.map { node => s"${node.clusterId}:${node.nodeId}:${node.httpPort}:${node.httpsPort}"}
            })

          }
        }
      }
    }

    val containerConfigListener = new UpdateListener[ContainerConfiguration] {
      var initialized = false

      override def configurationUpdated(configurationObject: ContainerConfiguration): Unit = {
        //Any change to this results in a restart of all nodes
        currentContainerConfig.set(configurationObject)

        nodeModificationLock.synchronized {
          logger.debug({
            "ALL Nodes restarted (Container Config updated): " +
              activeNodes.map { node => s"${node.clusterId}:${node.nodeId}:${node.httpPort}:${node.httpsPort}"}
          })
          activeNodes = activeNodes.map { node =>
            val n1 = node.restart()
            n1.start()
            n1
          }
        }

        //This might be the best way to trigger this without blocking
        //We make a call to update nodes in here because during startup, I might have received a systemmodel update before
        // getting a container config, so at that point I need to trigger a refresh of the nodes
        updateNodes()
      }

      override def isInitialized: Boolean = {
        initialized
      }
    }

    val systemModelConfigListener = new UpdateListener[SystemModel] {
      var initialized = false

      override def configurationUpdated(configurationObject: SystemModel): Unit = {
        currentSystemModel.set(configurationObject)
        //Set the current system model, and just update the nodes.
        updateNodes()
      }

      override def isInitialized: Boolean = {
        initialized
      }
    }


    //Only subscribe to the config files when told to start
    //Stupid APIs are stupid and also dumb
    configService.subscribeTo[ContainerConfiguration]("container.cfg.xml", containerXsdUrl, containerConfigListener, classOf[ContainerConfiguration])
    configService.subscribeTo[SystemModel]("system-model.cfg.xml", systemModelXsdURL, systemModelConfigListener, classOf[SystemModel])

    //Stay running, so that the thing doesn't exit or something
    //TODO: have to set up the core spring stuff first, before we can create per-node contexts

    //Await this latch forever!, better than a runloop
    runLatch.await() //This blocks this guy, so that the run thread keeps wedged here

    //Deregister from configs, will only happen after the runlatch has been released
    configService.unsubscribeFrom("container.cfg.xml", containerConfigListener)
    configService.unsubscribeFrom("system-model.cfg.xml", systemModelConfigListener)

    //Stop all local nodes
    nodeModificationLock.synchronized {
      activeNodes.foreach { n =>
        n.shutdown()
      }
      activeNodes = Set.empty[ReposeJettyServer]
    }
    0
  }


  /**
   * This will destroy the bean and shut it all down
   */
  override def destroy(): Unit = {
    runLatch.countDown()
  }
}
