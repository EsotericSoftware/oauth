/* Copyright (c) 2017, Nathan Sweet
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following
 * conditions are met:
 * 
 * - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution.
 * - Neither the name of Esoteric Software nor the names of its contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

package com.esotericsoftware.oauth;

import static com.esotericsoftware.minlog.Log.*;

import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.esotericsoftware.jsonbeans.JsonReader;
import com.esotericsoftware.jsonbeans.JsonValue;

import shaded.org.apache.http.HttpEntity;
import shaded.org.apache.http.client.methods.CloseableHttpResponse;
import shaded.org.apache.http.client.methods.HttpPost;
import shaded.org.apache.http.entity.StringEntity;
import shaded.org.apache.http.impl.client.CloseableHttpClient;
import shaded.org.apache.http.impl.client.HttpClients;
import shaded.org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import shaded.org.apache.http.util.EntityUtils;

/** @author Nathan Sweet */
public class OAuth {
	private final String category;
	private final CloseableHttpClient http;
	private final String clientID;
	private final String redirectURL, authorizeURL, accessTokenURL;
	private final String scopes;
	private String clientSecret;

	/** @param connectionPoolSize The number of threads that can make HTTP requests concurrently. */
	public OAuth (String category, String clientID, String redirectURL, String authorizeURL, String accessTokenURL, String scopes,
		int connectionPoolSize) {
		this.category = category;
		this.clientID = clientID;
		this.redirectURL = redirectURL;
		this.authorizeURL = authorizeURL;
		this.accessTokenURL = accessTokenURL;
		this.scopes = scopes;

		PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
		connectionManager.setMaxTotal(connectionPoolSize);
		connectionManager.setDefaultMaxPerRoute(connectionPoolSize);
		http = HttpClients.custom().setConnectionManager(connectionManager).build();
	}

	public OAuth (String category, String clientID, String redirectURL, String authorizeURL, String accessTokenURL, String scopes,
		CloseableHttpClient http) {
		this.category = category;
		this.clientID = clientID;
		this.redirectURL = redirectURL;
		this.authorizeURL = authorizeURL;
		this.accessTokenURL = accessTokenURL;
		this.scopes = scopes;
		this.http = http;
	}

	/** Initializes the specified token, if necessary.
	 * @return true when a new access token was needed. */
	public boolean authorize (Token token) throws IOException {
		if (token.accessToken != null) return false;
		obtainAccessToken(token, authorizeURL //
			+ "?client_id=" + URLEncoder.encode(clientID, "UTF-8") //
			+ "&response_type=code" //
			+ "&redirect_uri=" + URLEncoder.encode(redirectURL, "UTF-8") //
			+ "&scope=" + URLEncoder.encode(scopes, "UTF-8"));
		return true;
	}

	/** Called when a new access token is needed. The default implementation throws UnsupportedOperationException unless a
	 * {@link #setClientSecret(String) client secret} has been set.
	 * <p>
	 * Override to have the user visit the specified URL and allow access. Then the user is forwarded with a one-time use
	 * authorization code to the {@link #redirectURL}, which is your web service that uses the authorization code to obtain an
	 * accessToken, refreshToken, and expirationMillis. Retrieve those from your web service and set the fields on the specified
	 * token. The web service should only give the access token to authenticated users.
	 * <p>
	 * The web service obtains the access token by doing an HTTP POST to {@link #accessTokenURL} with a POST body of:
	 * <code>code=usersAuthCode&redirect_uri=yourRedirectURL&client_id=yourClientID&<b>client_secret=yourClientSecret</b>&grant_type=authorization_code</code>
	 * Obtaining the access token requires your client secret (bold), which ensures only your app can approve access. Your web
	 * service ensures the client secret is not leaked and only gives an access token to users it has authenticated.
	 * <p>
	 * Distributing the client secret inside your app can result in the client secret being extracted and used to impersonate your
	 * app. Only use {@link #setClientSecret(String)} if the application is used in a secure enviroment. For example, when the
	 * client secret is owned by the user running the application and the application containing the client secret is not
	 * distributed to others.
	 * <p>
	 * If a client secret has been set, the default implementation opens the specified URL in a browser and prompts the user to
	 * paste the authorization code at the command line. Next the authorization code and client secret are used to obtain an access
	 * token. The specified token is updated and ready to use when this method returns. */
	protected void obtainAccessToken (Token token, String url) throws IOException {
		if (clientSecret == null) throw new UnsupportedOperationException();

		if (INFO) info(category, "Visit this URL, allow access, and paste the new URL:\n" + url);
		try {
			Desktop.getDesktop().browse(new URI(url));
		} catch (Exception ignored) {
		}
		String authorizationCode = new BufferedReader(new InputStreamReader(System.in)).readLine();
		if (authorizationCode.contains("code=")) {
			Pattern pattern = Pattern.compile("code=([^&]+)&?");
			Matcher matcher = pattern.matcher(authorizationCode);
			if (matcher.find()) authorizationCode = matcher.group(1);
		}

		if (TRACE) trace(category, "Requesting access token.");
		JsonValue json = post(accessTokenURL, //
			"code=" + URLEncoder.encode(authorizationCode, "UTF-8") //
				+ "&redirect_uri=" + URLEncoder.encode(redirectURL, "UTF-8") //
				+ "&client_id=" + URLEncoder.encode(clientID, "UTF-8") //
				+ "&client_secret=" + URLEncoder.encode(clientSecret, "UTF-8") //
				+ "&grant_type=authorization_code");
		try {
			token.refreshToken = json.getString("refresh_token", null);
			token.accessToken = json.getString("access_token");
			token.expirationMillis = System.currentTimeMillis() + json.getInt("expires_in", Integer.MAX_VALUE) * 1000;
		} catch (Throwable ex) {
			throw new IOException("Invalid access token response" + (json != null ? ": " + json : "."), ex);
		}

		if (INFO) info(category, "Access token stored.");
	}

	/** Refreshes the access token, if necessary. Call this method just before each use of the access token. Some OAuth access
	 * tokens never expire and do not provide a refresh token, in which case this method is not needed.
	 * @return true if the token was refreshed. */
	public boolean refreshAccessToken (Token token) {
		if (!token.isExpired()) return false;
		if (TRACE) trace(category, "Refreshing access token.");

		if (token.refreshToken == null) {
			if (ERROR) error(category, "Refresh token is missing.");
			return false;
		}

		JsonValue json = null;
		try {
			json = post(accessTokenURL, //
				"refresh_token=" + URLEncoder.encode(token.refreshToken, "UTF-8") //
					+ "&client_id=" + URLEncoder.encode(clientID, "UTF-8") //
					+ "&client_secret=" + URLEncoder.encode(clientSecret, "UTF-8") //
					+ "&grant_type=refresh_token");
			token.accessToken = json.getString("access_token");
			token.expirationMillis = System.currentTimeMillis() + json.getInt("expires_in") * 1000;
			if (INFO) info(category, "Access token refreshed.");
			return true;
		} catch (Throwable ex) {
			if (ERROR) error(category, "Error refreshing access token" + (json != null ? ": " + json : "."), ex);
			return false;
		}
	}

	private JsonValue post (String url, String postBody) throws IOException {
		HttpPost request = new HttpPost(url);
		request.setEntity(new StringEntity(postBody));
		request.setHeader("Content-Type", "application/x-www-form-urlencoded");

		HttpEntity entity = null;
		CloseableHttpResponse response = null;
		try {
			response = http.execute(request);
			String body = "";
			entity = response.getEntity();
			if (entity != null) {
				Scanner scanner = null;
				try {
					scanner = new Scanner(entity.getContent(), "UTF-8").useDelimiter("\\A");
					if (scanner.hasNext()) body = scanner.next().trim();
				} finally {
					if (scanner != null) {
						try {
							scanner.close();
						} catch (Throwable ignored) {
						}
					}
				}
			}

			int status = response.getStatusLine().getStatusCode();
			if (status < 200 || status >= 300)
				throw new IOException(response.getStatusLine().toString() + (body.length() > 0 ? "\n" + body : ""));
			return new JsonReader().parse(body);
		} finally {
			if (entity != null) EntityUtils.consumeQuietly(entity);
			if (response != null) {
				try {
					response.close();
				} catch (Throwable ignored) {
				}
			}
		}
	}

	public String getClientID () {
		return clientID;
	}

	/** @return May be null. */
	public String getClientSecret () {
		return clientSecret;
	}

	/** Sets the client secret for obtaining an access token. See {@link #obtainAccessToken(Token, String)} for the security
	 * implications of embedded the client secret in your application. */
	public void setClientSecret (String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getRedirectURL () {
		return redirectURL;
	}

	public String getAuthorizeURL () {
		return authorizeURL;
	}

	public String getAccessTokenURL () {
		return accessTokenURL;
	}

	public String getScopes () {
		return scopes;
	}

	static public class Token {
		public String refreshToken;
		public String accessToken;
		public long expirationMillis;

		public boolean isExpired () {
			return expirationMillis < System.currentTimeMillis();
		}
	}
}
