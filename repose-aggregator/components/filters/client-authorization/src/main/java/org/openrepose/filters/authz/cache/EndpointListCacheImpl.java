package org.openrepose.filters.authz.cache;

import org.openrepose.core.services.datastore.Datastore;

import java.io.IOException;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 *
 * @author zinic
 */
public class EndpointListCacheImpl implements EndpointListCache {

   private static final String ENDPOINT_CACHE_NS = "components.rackspace.authz.cache.";
   private final Datastore cacheInstance;
   private final int ttlInSeconds;

   public EndpointListCacheImpl(Datastore cacheInstance, int ttlInSeconds) {
      this.cacheInstance = cacheInstance;
      this.ttlInSeconds = ttlInSeconds;
   }

   public static String getCacheNameForToken(String token) {
      return ENDPOINT_CACHE_NS + token;
   }

   @Override
   public List<CachedEndpoint> getCachedEndpointsForToken(String token) {
      final String cacheName = getCacheNameForToken(token);
      return (List<CachedEndpoint>)cacheInstance.get(cacheName);
   }

   @Override
   public void cacheEndpointsForToken(String token, List<CachedEndpoint> endpoints) throws IOException {
      // If the list passed is not serializable then copy it into a serializable list
      final Serializable serializable = endpoints instanceof Serializable ? (Serializable) endpoints : new LinkedList(endpoints);
      final String cacheName = getCacheNameForToken(token);

      cacheInstance.put(cacheName, serializable, ttlInSeconds, TimeUnit.SECONDS);
   }
}
