package org.benetech.security.client.digest;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.client.AuthCache;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.impl.auth.DigestScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

/**
 * Factory to create HttpContext client objects that can use Digest Authentication.
 * 
 * @see <a href=
 *      "http://www.baeldung.com/resttemplate-digest-authentication">http://www.baeldung.com/resttemplate-digest-authentication</a>
 * @author Eugen Paraschiv <http://www.baeldung.com/author/eugen/>
 *
 */
public class HttpComponentsClientHttpRequestFactoryDigestAuth
    extends HttpComponentsClientHttpRequestFactory {

  private static Log logger =
      LogFactory.getLog(HttpComponentsClientHttpRequestFactoryDigestAuth.class);

  HttpHost host;
  String realmName;
  InetSocketAddress proxyAddress;

  public HttpComponentsClientHttpRequestFactoryDigestAuth(InetSocketAddress proxyAddress) {
    super();
    this.proxyAddress = proxyAddress;
  }

  @Override
  protected HttpContext createHttpContext(HttpMethod httpMethod, URI uri) {

    return createHttpContext();
  }

  private HttpContext createHttpContext() {
    // Create AuthCache instance
    AuthCache authCache = new BasicAuthCache();
    // Generate DIGEST scheme object, initialize it and add it to the local auth cache
    DigestScheme digestAuth = new DigestScheme();
    // If we already know the realm name
    digestAuth.overrideParamter("realm", realmName);
    
    String nonceString = Long.toString(new Random().nextLong(), 36);
    
    digestAuth.overrideParamter("nonce", nonceString);

    if (logger.isDebugEnabled()) {
      logger.debug("DigestAuth params Nonce " + nonceString + " Realm " + realmName);
    }
    
    authCache.put(host, digestAuth);

    // Add AuthCache to the execution context
    BasicHttpContext localcontext = new BasicHttpContext();
    localcontext.setAttribute(ClientContext.AUTH_CACHE, authCache);
    
    // Proxy for debugging
    if (proxyAddress != null) {
      localcontext.setAttribute("socks.address", proxyAddress);
    }
    return localcontext;
  }

  public HttpHost getHost() {
    return host;
  }

  public void setHost(HttpHost host) {
    this.host = host;
  }

  public String getRealmName() {
    return realmName;
  }

  public void setRealmName(String realmName) {
    this.realmName = realmName;
  }



}
