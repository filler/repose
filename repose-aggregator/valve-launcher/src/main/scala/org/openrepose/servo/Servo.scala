package org.openrepose.servo

import java.io.{File, InputStream, PrintStream}
import java.util.Properties

object Servo {

  /**
   * Command line configuration
   * @param configDirectory the root configuration directory (even though it's called --config-file)
   * @param executionString A secret command allowing me to not execute repose, but something else instead
   * @param insecure whether or not to be super insecure
   */
  case class ServoConfig(configDirectory: File = new File("/etc/repose"),
                         executionString: String = "java -jar /path/to/jetty.jar /path/to/repose/war",
                         insecure: Boolean = false)


  /**
   * Basically just runs what would be in Main, but gives me the ability to test it
   * @param args the String passed into the program
   * @param in Typically standard in
   * @param out typically standard out
   * @param err typically standard err
   * @return the exit code
   */
  def execute(args: Array[String], in: InputStream, out: PrintStream, err: PrintStream):Int = {

    //In this specific method, we're going to redirect the console output
    //This is so that Option parser uses our stuff, and we can caputre console output!
    Console.setOut(out)
    Console.setIn(in)
    Console.setErr(err)

    //Load up the main.properties
    val props = new Properties()
    props.load(this.getClass.getResourceAsStream("/main.properties"))

    val reposeVersion = props.getProperty("version", "UNKNONWN")

    /**
     * Yeah this looks ugly in IntelliJ, but it comes out glorious on the console. (looks great in vim)
     * For reference: http://patorjk.com/software/taag/#p=display&h=1&v=1&f=ANSI%20Shadow&t=SERVO
     * Also of note, string interpolation got upset with the fancy ascii characters, so doing two operations
     */
    val fancyString =
      """
        |███████╗███████╗██████╗ ██╗   ██╗ ██████╗
        |██╔════╝██╔════╝██╔══██╗██║   ██║██╔═══██╗  I'm in your base,
        |███████╗█████╗  ██████╔╝██║   ██║██║   ██║  launching your Valves.
        |╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║   ██║  Version $version
        |███████║███████╗██║  ██║ ╚████╔╝ ╚██████╔╝
        |╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝   ╚═════╝
      """.stripMargin.replace("$version", reposeVersion)

    val parser = new scopt.OptionParser[ServoConfig]("servo") {
      head(fancyString)
      opt[File]('c', "config-file") action { (x, c) =>
        c.copy(configDirectory = x)
      } validate { f =>
        if (f.exists() && f.canRead()) {
          success
        } else {
          failure(s"Unable to read from directory: ${f.getAbsolutePath}")
        }
      } text s"The root configuration directory for Repose (where your system-model is) Default: /etc/repose"
      opt[Unit]('k', "insecure") action { (_, c) =>
        c.copy(insecure = true)
      } text "Ignore all SSL certificates validity and operate VERY insecurely Default: off (validate certs)"
      opt[String]('x', "execute") hidden() action { (x, c) =>
        c.copy(executionString = x)
      } text "What should this command try to execute (TESTING USE ONLY)"
    }

    parser.parse(args, ServoConfig()) map { config =>
      //Got a valid config
      out.println("ZOMG WOULDVE STARTED VALVE")
      serveValves(config)
      0
    } getOrElse {
      //Nope, not a valid config
      //Return the exit code
      1
    }

  }

  def serveValves(config: ServoConfig) = {
    //Create a listener on the Config root system-model.cfg.xml
    //On the first start up, and any time the system-model changes:
    // *Get the list of nodes
    // *Identify the localhost nodes
    // *Fork a jetty running the war file for each one.
    // *If they are already running, do nothing, if there are orphaned nodes, kill em
    //Don't exit
    println("NOPE")
  }


}