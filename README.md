# Simple OAuth for Java

This library is a single file which makes using OAuth 2.0 from Java very easy.

## Examples

For simplicity, these examples set the client secret. Keep in mind that embedding the client secret has [security implications](#Security), though it still makes sense for some scenarios.

### Slack

Create the OAuth instance:

```java
OAuth oauth = new OAuth("slack", "yourClientID",
	"yourRedirectURL",
	"https://slack.com/oauth/authorize", // authorize URL
	"https://slack.com/api/oauth.access", // access token URL
	"dnd:write", // scopes (for "do not disturb")
	4); // concurrent HTTP requests
oauth.setClientSecret("yourClientSecret"); // Note security implications below.
```

Create/load and initialize a `Token` instance:

```java
Token token = ... // Load token from disk.
if (oauth.authorize(token)) {
	// Save token to disk.
}
```

Finally, use the access token to make requests:

```java
// Slack access tokens never expire, so just use the access token.
HttpGet request = new HttpGet("https://slack.com/api/dnd.setSnooze?num_minutes=60");
request.setHeader("Authorization", "Bearer " + token.accessToken);
httpRequest(request);
```

### Spotify

```java
oauth = new OAuth("spotify", "yourClientID",
	"yourRedirectURL",
	"https://accounts.spotify.com/authorize", // authorize URL
	"https://accounts.spotify.com/api/token", // access token URL
	"user-modify-playback-state", // scopes
	4); // concurrent HTTP requests
oauth.setClientSecret("yourClientSecret"); // Note security implications below.

...

Token token = ... // Load token from disk.
if (oauth.authorize(token)) {
	// Save token to disk.
}

...

// Spotify access tokens expire, so call refreshAccessToken just before using the access token.
private boolean refreshToken () {
	return switch (oauth.refreshAccessToken(state.token)) {
	case valid -> true; // Hasn't expired yet.
	case refreshed -> {
		// Save refreshed token to disk.
		yield true;
	}
	case revoked -> { // Need to authorize again.
		if (oauth.authorize(token)) {
			// Save new token to disk.
			yield true;
		}
		yield false;
	}
	case failed -> false;
	};
}
if (refreshToken()) {
	HttpPut request = new HttpPut("https://api.spotify.com/v1/me/player/play");
	request.setHeader("Authorization", "Bearer " + accessToken);
	httpRequest(request);
}
```

### Google

```java
oauth = new OAuth("google", "yourClientID",
	"urn:ietf:wg:oauth:2.0:oob", // redirect URL
	"https://accounts.google.com/o/oauth2/v2/auth", // authorize URL
	"https://www.googleapis.com/oauth2/v4/token", // access token URL
	"https://www.googleapis.com/auth/assistant-sdk-prototype", // scopes (for Google Assistant)
	4); // concurrent HTTP requests
oauth.setClientSecret("yourClientSecret"); // Note security implications below.

...

Token token = ... // Load token from disk.
if (oauth.authorize(token)) {
	// Save token to disk.
}

...

EmbeddedAssistantGrpc.EmbeddedAssistantStub client;
client = EmbeddedAssistantGrpc.newStub(ManagedChannelBuilder.forAddress("embeddedassistant.googleapis.com", 443).build());

if (refreshToken()) { // From above.
	// Google's stuff to set the access token.
	OAuth2Credentials credentials = new OAuth2Credentials(new AccessToken(accessToken, new Date(expirationTime)));
	client = client.withCallCredentials(MoreCallCredentials.from(credentials));
	// Google's stuff to use the Google Assistant API.
	StreamObserver<ConverseResponse> observer = ...
	client.converse(observer);
}
```

## Security

The examples above embed the client secret in the application, which only makes sense if the application is used in a secure enviroment. For example, when the client secret is owned by the user running the application and the application containing the client secret is not distributed to others. Otherwise, the client secret can be extracted and used to impersonate the application.

If a client secret has been set, the default implementation opens the specified URL in a browser and prompts the user to paste the authorization code at the command line. Next the authorization code and client secret are used to obtain an access token, which is ready for the application to use.

If a client secret has not been set, then the `obtainAuthorizationCode` method must be overridden:

```java
oauth = new OAuth("someService", "yourClientID",
	"yourRedirectURL",
	"serviceAuthorizeURL",
	"serviceAccessTokenURL",
	"serviceScopes", 
	4
) {
	protected void obtainAuthorizationCode (String authorizationUrl) throws IOException {
		// your code here
	}
}
```

The `obtainAuthorizationCode` method should have the user visit the specified `url` and allow access. Then the user is forwarded with a one-time use authorization code to `yourRedirectURL`, which is your web service that uses the authorization code to obtain an access token, refresh token, and expiration milliseconds. The application should retrieve those from your web service and set the corresponding 3 fields on the specified `token`. The web service should only give the access token to authenticated users.

The web service obtains the access token, refresh token, and expiration milliseconds by doing an HTTP POST to `serviceAccessTokenURL` with a POST body of:

```
code=usersAuthorizationCode&redirect_uri=yourRedirectURL&client_id=yourClientID&client_secret=yourClientSecret&grant_type=authorization_code
```

Obtaining the access token requires your client secret which is only accessible to your web service, ensuring only your app can approve access. Your web service ensures the client secret is not leaked and only gives an access token to users it has authenticated.

## Utilities

### JsonBeans

[JsonBeans](https://github.com/EsotericSoftware/jsonbeans/) is used by the `OAuth` class and makes it easy to save/load the `Token` instance:

```java
File file = ...
Json json = new Json();
Token token = file.exists() ? json.fromJson(Token.class, file) : new Token();
if (oauth.authorize(token)) {
	json.toJson(token, new FileWriter(file));
}
```

### HttpClient

Most of the examples above use [Apache HttpClient](https://hc.apache.org/httpcomponents-client-ga/), which the `OAuth` class depends on. Here is the `httpRequest` method:

```java
int connectionPoolSize = 4;
PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
connectionManager.setMaxTotal(connectionPoolSize);
connectionManager.setDefaultMaxPerRoute(connectionPoolSize);
CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();

...

public String httpRequest (HttpUriRequest request) throws IOException {
	HttpEntity entity = null;
	try (CloseableHttpResponse response = httpClient.execute(request)) {
		String body = "";
		entity = response.getEntity();
		if (entity != null) {
			InputStream input = entity.getContent();
			if (input != null) {
				try (Scanner scanner = new Scanner(input, "UTF-8").useDelimiter("\\A")) {
					if (scanner.hasNext()) body = scanner.next().trim();
				}
			}
		}

		int status = response.getStatusLine().getStatusCode();
		if (status < 200 || status >= 300)
			throw new IOException(response.getStatusLine().toString() + (body.length() > 0 ? "\n" + body : ""));
		return body;
	} finally {
		if (entity != null) EntityUtils.consumeQuietly(entity);
	}
}
```

If using HttpClient in your app like this, `httpClient` can be passed to the `OAuth` constructor to share the same instance.

### Logging

[MinLog](https://github.com/EsotericSoftware/minlog/) is used for logging, which is easily disabled or redirected.
