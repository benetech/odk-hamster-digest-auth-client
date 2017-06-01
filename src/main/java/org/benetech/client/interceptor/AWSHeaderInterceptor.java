package org.benetech.client.interceptor;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

/**
 * Amazon is remapping the WWW-Authenticate header we need for digest
 * authentication.
 * We need to map it back.
 * @See https://forums.aws.amazon.com/message.jspa?messageID=730337
 *
 */
public class AWSHeaderInterceptor implements ClientHttpRequestInterceptor {
  
  private static final Map<String, String> headerMap;
  
  private static Log logger = LogFactory.getLog(AWSHeaderInterceptor.class);

  
  static {
      Map<String, String> headers = new HashMap<String,String>();
      // Add any additional headers to be remapped here
      headers.put("x-amzn-remapped-www-authenticate", HttpHeaders.WWW_AUTHENTICATE);
      headerMap = Collections.unmodifiableMap(headers);
  }
  
  @Override
  public ClientHttpResponse intercept(HttpRequest request, byte[] body,
      ClientHttpRequestExecution execution) throws IOException {
    ClientHttpResponse response = execution.execute(request, body);
    HttpHeaders headers = response.getHeaders();
    
    // Avoid java.util.ConcurrentModificationException
    HttpHeaders newHeaders = new HttpHeaders();
    for (String header : headers.keySet()) {
      if (headerMap.get(header.toLowerCase()) != null) {
  
        List<String> oldValues = response.getHeaders().get(header);
        if (logger.isDebugEnabled()) {
          logger.debug("Found header " + header + ": " + oldValues.toString());
        }
        newHeaders.put(HttpHeaders.WWW_AUTHENTICATE, oldValues);
      }
    }
    for (String newHeader : newHeaders.keySet()) {
      response.getHeaders().put(newHeader, newHeaders.get(newHeader));
    }

    return response;
  }

}
