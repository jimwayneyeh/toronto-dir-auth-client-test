package org.twgogo.jimwayne.toronto.directory.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.twgogo.jimwayne.utilities.StreamReader;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class Authentication {
	private static CloseableHttpClient HTTP_CLIENT = null;

	private Logger log = LoggerFactory.getLogger("Authorization");
	
	// ---------------------------------------- //
	//       Initiate constant variables.       //
	// ---------------------------------------- //
	private static final String HEADER_NO_CACHE = "no-cache";
	private static final String HEADER_MEDIATYPE_JSON = "application/json";
	
	// ------------------------------------------------------------------------------------------------ //
	//       Initiate URI variables which will be used as access end points of directory service.       //
	// ------------------------------------------------------------------------------------------------ //
	private static String DIR_BASE_URI = null;
	private static URI URI_LOGIN = null;
	private static URI URI_CREATE_TENANT = null;
	private static URI URI_CREATE_USER = null;
	private static URI URI_DELETE_TENANT = null;
	private static URI URI_DELETE_USER = null;
	private static URI URI_VERIFY_TICKET = null;
	
	static {
		try {
			// TODO Ignore the SSL certificate and host name verifier which should not be ignored in production.
			SSLContextBuilder sslBuilder = new SSLContextBuilder();
			sslBuilder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
			SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
					sslBuilder.build(), 
					new TrustAllHostNameVerifier());
				
			HTTP_CLIENT = HttpClients.custom().setSSLSocketFactory(sslsf).build();
		} catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
			e.printStackTrace();
		}
	}
	
	public Authentication (String hostAddr) {
		DIR_BASE_URI = "https://" + hostAddr + "/dir/services";
		
		// --------------------------------------------------------------------------------- //
		//       Initiate the URI which may be used while accessing directory service.       //
		// --------------------------------------------------------------------------------- //
	
		try {
			URI_LOGIN = new URI(DIR_BASE_URI + "/auth/login");
			URI_CREATE_TENANT = new URI(DIR_BASE_URI + "/dir_mgt/create_tenant");
			URI_CREATE_USER = new URI(DIR_BASE_URI + "/dir_user/create_user");
			URI_DELETE_TENANT = new URI(DIR_BASE_URI + "/dir_mgt/delete_tenant");
			URI_DELETE_USER = new URI(DIR_BASE_URI + "/dir_user/delete_user");
			URI_VERIFY_TICKET = new URI(DIR_BASE_URI + "/auth/verify_ticket");
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
	}
	
	public String login (String tenantId, String userName, String password) {
		HttpPost postRequest = null;
		try {
			// ---------------------------------- //
			//       Construct the request.       //
			// ---------------------------------- //
			JsonObject postJSON = new JsonObject();
			if(StringUtils.isNotEmpty(tenantId)) postJSON.addProperty("tenant_id", tenantId);
			postJSON.addProperty("username", userName);
			postJSON.addProperty("password", password);
			log.debug("Post body for login: {}", postJSON);
			
			StringEntity requestBody = new StringEntity(postJSON.toString(), Charset.forName("UTF-8"));
			postRequest = (HttpPost) getHttpRequest(HttpMethod.POST, URI_LOGIN, requestBody);
			log.debug("Post request {}", postRequest);
			
			// ---------------------------------------------------- //
			//       Send the request and parse the response.       //
			// ---------------------------------------------------- //
			HttpResponse response = sendHttpRequest(postRequest);
			String ticket = response.ResponseBody.get("ticket").getAsString();
			return ticket;
		} finally {
			if (postRequest != null) postRequest.releaseConnection();
		}
	}
	
	public String createTenant (String adminTicket, String tenantName) {
		// TODO Create default privilege to fulfill the requirement of directory's API.
		JsonObject priviledge = new JsonObject();
		priviledge.add("_file_sync", new JsonParser().parse("{'_quota': 0, '_download_band': 0, '_upload_band': 0, '_version_count': 0}"));
		
		HttpPost postRequest = null;
		try {
			// ---------------------------------- //
			//       Construct the request.       //
			// ---------------------------------- //
			JsonObject postJSON = new JsonObject();
			postJSON.addProperty("tenant_name", tenantName);
			postJSON.add("privileges", priviledge);
			log.debug("Post body for creating tenant: {}", postJSON);
			
			StringEntity requestBody = new StringEntity(postJSON.toString(), Charset.forName("UTF-8"));
			postRequest = (HttpPost) getHttpRequest(HttpMethod.POST, URI_CREATE_TENANT, requestBody);
			postRequest.addHeader(HttpHeaders.AUTHORIZATION, adminTicket);
			log.debug("Post request {}", postRequest);
			
			// ---------------------------------------------------- //
			//       Send the request and parse the response.       //
			// ---------------------------------------------------- //
			HttpResponse response = sendHttpRequest(postRequest);
			String tenantId = response.ResponseBody.get("tenant_id").getAsString();
			return tenantId;
		} finally {
			if (postRequest != null) postRequest.releaseConnection();
		}
	}
	
	public void createUser (String adminTicket, String tenantId, String userName, String password, String firstName, String lastName, String mailAddr) {
		HttpPost postRequest = null;
		try {
			// ---------------------------------- //
			//       Construct the request.       //
			// ---------------------------------- //
			JsonObject postJSON = new JsonObject();
			postJSON.addProperty("tenant_id", tenantId);
			postJSON.addProperty("username", userName);
			postJSON.addProperty("password", password);
			postJSON.addProperty("firstname", firstName);
			postJSON.addProperty("lastname", lastName);
			postJSON.addProperty("mail", mailAddr);
			log.debug("Post body for creating an user: {}", postJSON);
			
			StringEntity requestBody = new StringEntity(postJSON.toString(), Charset.forName("UTF-8"));
			postRequest = (HttpPost) getHttpRequest(HttpMethod.POST, URI_CREATE_USER, requestBody);
			postRequest.addHeader(HttpHeaders.AUTHORIZATION, adminTicket);
			log.debug("Post request {}", postRequest);
			
			// ---------------------------------------------------- //
			//       Send the request and parse the response.       //
			// ---------------------------------------------------- //
			sendHttpRequest(postRequest);
		} finally {
			if (postRequest != null) postRequest.releaseConnection();
		}
	}
	
	// TODO
	public void deleteTenant (String adminTicket, String tenantId) {
		URI requestURI = null;
		
		try {
			requestURI = new URI(URI_DELETE_TENANT.toString(), "?tenant_id=", tenantId);
		} catch (URISyntaxException e) {
			throw new IllegalAccessError();
		}
		// ---------------------------------- //
		//       Construct the request.       //
		// ---------------------------------- //
		HttpGet getRequest = (HttpGet) getHttpRequest(HttpMethod.GET, requestURI);
		getRequest.addHeader(HttpHeaders.AUTHORIZATION, adminTicket);
		log.debug("Get request {}", getRequest);
		
		// ---------------------------------------------------- //
		//       Send the request and parse the response.       //
		// ---------------------------------------------------- //
		HttpResponse response = sendHttpRequest(getRequest);
	}
	
	// TODO
	public String deleteUser (String adminTicket, String tenantName) {
		/*HttpPost postRequest = null;
		try {
			// ---------------------------------- //
			//       Construct the request.       //
			// ---------------------------------- //
			JsonObject postJSON = new JsonObject();
			postJSON.addProperty("tenant_name", tenantName);
			postJSON.add("privileges", new JsonObject());
			log.debug("Post body for creating tenant: {}", postJSON);
			
			StringEntity requestBody = new StringEntity(postJSON.toString(), Charset.forName("UTF-8"));
			postRequest = (HttpPost) getHttpRequest(HttpMethod.POST, URI_CREATE_TENANT, requestBody);
			postRequest.addHeader(HttpHeaders.AUTHORIZATION, adminTicket);
			log.debug("Post request {}", postRequest);
			
			// ---------------------------------------------------- //
			//       Send the request and parse the response.       //
			// ---------------------------------------------------- //
			HttpResponse response = sendHttpRequest(postRequest);
			String tenantId = response.ResponseBody.get("tenant_id").getAsString();
			return tenantId;
		} finally {
			if (postRequest != null) postRequest.releaseConnection();
		}*/
		return null;
	}
	
	private HttpUriRequest getHttpRequest(HttpMethod method, URI uri)
			throws IllegalArgumentException, IllegalAccessError {
		return this.getHttpRequest(method, uri);
	}
	
	private HttpUriRequest getHttpRequest(HttpMethod method, URI uri, HttpEntity entity)
			throws IllegalArgumentException, IllegalAccessError {
		HttpRequestBase request = null;

		// Get request method according to the given method.
		switch (method) {
		case GET:
			request = new HttpGet(uri);
			break;
		case POST:
			HttpPost postRequest = new HttpPost(uri);
			if(entity != null) postRequest.setEntity(entity);
			request = postRequest;
			break;
		default:
			throw new IllegalArgumentException();
		}

		// Initiate the request with common headers.
		request.addHeader(HttpHeaders.CONTENT_TYPE, HEADER_MEDIATYPE_JSON);
		request.addHeader(HttpHeaders.CACHE_CONTROL, HEADER_NO_CACHE);

		return request;
	}
	
	/**
	 * 
	 * @param request
	 * @return
	 * @throws IllegalAccessError The responded HTTP status code and JSON status code is not 200 and 0, respectively.
	 */
	private HttpResponse sendHttpRequest (HttpUriRequest request) throws IllegalAccessError {
		Logger log = LoggerFactory.getLogger("HttpRequestSender");
		
		try (CloseableHttpResponse httpResponse = HTTP_CLIENT.execute(request)) {
			// Get the HTTP status code.
			int httpStatuscode = httpResponse.getStatusLine().getStatusCode();
			
			// Declare the JSON status code and the responded JSON.
			int statusCode = -1;
			JsonObject responseJSON = null;

			// ------------------------------------ //
			//       Parse the response body.       //
			// ------------------------------------ //
			HttpEntity responseEntity = null;
			try {
				responseEntity = httpResponse.getEntity();
				InputStream stream = responseEntity.getContent();
				
				responseJSON = (JsonObject) new JsonParser().parse(
						StreamReader.get(stream, Charset.forName("UTF-8")));

				statusCode = responseJSON.get("statuscode").getAsInt();
				if (statusCode != 0) {
					log.debug("Fail to send the request. Responded code: {}, {}", httpStatuscode, statusCode);
					throw new IllegalAccessError("Code: " + statusCode);
				}
			} finally {
				if (responseEntity != null)
					EntityUtils.consumeQuietly(responseEntity);
			}
			
			return new HttpResponse(statusCode, responseJSON);
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private enum HttpMethod {
		/**
		 * HTTP GET method.
		 */
		GET,
		/**
		 * HTTP POST method.
		 */
		POST;

		@Override
		public String toString() {
			switch (this) {
			case GET:
				return "GET";
			case POST:
				return "POST";
			default:
				throw new IllegalArgumentException();
			}
		}
	}
	
	/**
	 * A class for representing the response of a HTTP request.
	 */
	private class HttpResponse {
		/**
		 * The responded HTTP status code.
		 */
		private int HttpStatusCode = -1;
		/**
		 * HTTP response body.
		 */
		private JsonObject ResponseBody = null;
		
		public HttpResponse (int statusCode, JsonObject body) {
			this.HttpStatusCode = statusCode;
			this.ResponseBody = body;
		}
	}
	
	private static class TrustAllHostNameVerifier implements HostnameVerifier {
	    public boolean verify(String hostname, SSLSession session) {
	        return true;
	    }
	}
}
