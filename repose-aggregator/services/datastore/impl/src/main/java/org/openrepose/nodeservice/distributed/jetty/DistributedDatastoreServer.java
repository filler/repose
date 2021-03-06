package org.openrepose.nodeservice.distributed.jetty;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.openrepose.nodeservice.distributed.servlet.DistributedDatastoreServlet;

/**
 * Perhaps encapsulate the monitoring bits better
 */
public class DistributedDatastoreServer {

    private final String clusterId;
    private final String nodeId;
    private final DistributedDatastoreServlet ddServlet;

    private int port;
    private Server server;

    public DistributedDatastoreServer(String clusterId,
                                      String nodeId,
                                      DistributedDatastoreServlet ddServlet
    ) {
        this.clusterId = clusterId;
        this.nodeId = nodeId;
        this.ddServlet = ddServlet;
    }

    /**
     * Start the server on a port. If it's already started on that port, it won't do anything at all.
     * If the port changes, the server will be stopped and a new one will be turned on using the same servlet.
     *
     * @param port
     * @throws Exception
     */
    public void runServer(int port) throws Exception {
        if (this.port != port) {
            if (server != null) {
                server.stop();
            }

            server = new Server();
            ServerConnector conn = new ServerConnector(server);
            conn.setPort(port);
            this.port = port; //Save the port so we know if it's changed
            server.addConnector(conn);

            ServletContextHandler rootContext = new ServletContextHandler(server, "/");

            ServletHolder holder = new ServletHolder(ddServlet);
            holder.setName("DistDatastoreServlet-" + clusterId + "-" + nodeId);
            rootContext.addServlet(holder, "/*");
            server.setHandler(rootContext);
            server.setStopAtShutdown(true);
            server.start();
        }
    }

    public void stop() throws Exception {
        if (server != null && server.isStarted()) {
            server.stop();
        }
    }

    public int getPort() {
        return port;
    }
}
