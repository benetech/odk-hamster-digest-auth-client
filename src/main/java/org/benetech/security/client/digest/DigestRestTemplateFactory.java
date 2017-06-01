package org.benetech.security.client.digest;

import java.net.InetSocketAddress;
import java.nio.charset.Charset;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.benetech.client.interceptor.AWSHeaderInterceptor;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

/**
 * Factory to create RestTemplate client objects that can use Digest Authentication.
 * 
 * @see <a href=
 *      "http://www.baeldung.com/resttemplate-digest-authentication">http://www.baeldung.com/resttemplate-digest-authentication</a>
 * @author Eugen Paraschiv <http://www.baeldung.com/author/eugen/>
 *
 */
public class DigestRestTemplateFactory {

  private static Log logger = LogFactory.getLog(DigestRestTemplateFactory.class);

  public static RestTemplate getRestTemplate(String hostname, int port, String scheme,
      String realmName, String username, String password) {
    return getRestTemplate(hostname, port, scheme, realmName, username, password, null, false);
  }
  
  public static RestTemplate getRestTemplate(String hostname, int port, String scheme,
      String realmName, String username, String password, boolean useAwsFilter) {
    return getRestTemplate(hostname, port, scheme, realmName, username, password, null, useAwsFilter);
  }


  public static RestTemplate getRestTemplate(String hostname, int port, String scheme,
      String realmName, String username, String password, InetSocketAddress proxy, boolean useAwsFilter) {
    HttpHost host = new HttpHost(hostname, port, scheme);


    HttpClientBuilder clientBuilder = HttpClientBuilder.create()
        .setDefaultCredentialsProvider(provider(username, password)).useSystemProperties();


    CloseableHttpClient client = clientBuilder.build();
    HttpComponentsClientHttpRequestFactoryDigestAuth requestFactory =
        new HttpComponentsClientHttpRequestFactoryDigestAuth(proxy);
    requestFactory.setHttpClient(client);
    requestFactory.setHost(host);
    requestFactory.setRealmName(realmName);

    RestTemplate restTemplate = new RestTemplate(requestFactory);
    // Add converters for multi-part form submission
    FormHttpMessageConverter formConverter = new FormHttpMessageConverter();
    formConverter.setCharset(Charset.forName("UTF8"));
    restTemplate.getMessageConverters().add(formConverter);
    restTemplate.getMessageConverters().add(new MappingJackson2HttpMessageConverter());
    if (useAwsFilter) {
      restTemplate.getInterceptors().add(0, new AWSHeaderInterceptor());
    }

    for (ClientHttpRequestInterceptor interceptor : restTemplate.getInterceptors()) {
      logger.info("interceptor " + interceptor.getClass().toString());
    }

    return restTemplate;
  }

  private static CredentialsProvider provider(String username, String password) {
    CredentialsProvider provider = new BasicCredentialsProvider();
    UsernamePasswordCredentials credentials = new UsernamePasswordCredentials(username, password);
    provider.setCredentials(AuthScope.ANY, credentials);
    return provider;
  }
}
