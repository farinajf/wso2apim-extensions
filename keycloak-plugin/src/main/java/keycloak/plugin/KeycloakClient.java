/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package keycloak.plugin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.impl.APIConstants;

/**
 *
 * @author fran
 */
public class KeycloakClient extends org.wso2.carbon.apimgt.impl.AbstractKeyManager {
    private static final Log    log   = LogFactory.getLog(KeycloakClient.class);
    private static final String _NAME = KeycloakClient.class.getName();

    private KeyManagerConfiguration configuration;

    /*-------------------------------------------------------------------------*/
    /*                Metodos privados                                         */
    /*-------------------------------------------------------------------------*/
    /**
     *
     * @param inicial
     * @param result
     */
    private void _inicia(final OAuthApplicationInfo inicial, final OAuthApplicationInfo result) {
        if (inicial == null) return;

        result.addParameter(Constantes.WSO2APIM.CLIENT_ID_ISSUED_AT,               inicial.getParameter(Constantes.WSO2APIM.CLIENT_ID_ISSUED_AT));
        result.addParameter(Constantes.WSO2APIM.CLIENT_URI,                        inicial.getParameter(Constantes.WSO2APIM.CLIENT_URI));
        result.addParameter(Constantes.WSO2APIM.CLIENT_LOGO_URI,                   inicial.getParameter(Constantes.WSO2APIM.CLIENT_LOGO_URI));
        result.addParameter(Constantes.WSO2APIM.CLIENT_APPLICATION_TYPE,           inicial.getParameter(Constantes.WSO2APIM.CLIENT_APPLICATION_TYPE));
        result.addParameter(Constantes.WSO2APIM.CLIENT_POST_LOGOUT_REDIRECT_URIS,  inicial.getParameter(Constantes.WSO2APIM.CLIENT_POST_LOGOUT_REDIRECT_URIS));
        result.addParameter(Constantes.WSO2APIM.CLIENT_RESPONSE_TYPES,             inicial.getParameter(Constantes.WSO2APIM.CLIENT_RESPONSE_TYPES));
        result.addParameter(Constantes.WSO2APIM.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD, inicial.getParameter(Constantes.WSO2APIM.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD));
        result.addParameter(Constantes.WSO2APIM.CLIENT_INITIATE_LOGIN_URI,         inicial.getParameter(Constantes.WSO2APIM.CLIENT_INITIATE_LOGIN_URI));
    }

    /**
     * Returns a space separate string from list of the contents in the string array.
     *
     * @param x an array of strings.
     * @return space separated string.
     */
    private static String _convertToString(final String[] x) {
        if (x == null) return null;

        final StringBuilder sb      = new StringBuilder();
        final List<String>  strList = Arrays.asList(x);

        for (String s : strList) sb.append(s).append(" ");

        return sb.toString().trim();
    }

    /**
     *
     * @return
     * @throws APIManagementException
     */
    private String _getAuthorization() throws APIManagementException {
        final StringBuilder result = new StringBuilder();
        BufferedReader      reader = null;

        log.info(_NAME + "._getAuthorization()");

        final String              accessTokenEndpoint = Constantes.Properties2.ACCESS_TOKEN_ENDPOINT;
        final CloseableHttpClient httpClient          = HttpClientBuilder.create().build();

        try
        {
            final StringBuilder payload = new StringBuilder();
            final HttpPost      post    = new HttpPost(accessTokenEndpoint);

            payload.append("username=").append (Constantes.Properties2.USERNAME);
            payload.append("&password=").append(Constantes.Properties2.PASSWORD);
            payload.append("&grant_type=password");
            payload.append("&client_id=").append    (Constantes.Properties2.CLIENT_ID);
            payload.append("&client_secret=").append(Constantes.Properties2.CLIENT_SECRET);

            post.setEntity(new StringEntity(payload.toString(), Constantes.UTF_8));
            post.setHeader(Constantes.HTTP_HEADER_CONTENT_TYPE, Constantes.HTTP_HEADER_CT_FORM_URL_ENCODED);

            final HttpResponse response   = httpClient.execute(post);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            log.info(_NAME + " response: " + response.toString());

            if (entity == null)
            {
                _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth: " + String.valueOf(response));
            }

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), Constantes.UTF_8));

            if (statusCode == HttpStatus.SC_OK)
            {
                final JSONObject jsonResponse = _getParsedObjectByReader(reader);
                log.info(_NAME + " jsonResponse: " + jsonResponse.toJSONString());

                final String access_token = (String) jsonResponse.get(Constantes.KEYCLOAK.ACCESS_TOKEN);

                result.append(Constantes.HTTP_HEADER_AUTH_BEARER).append(" ").append(access_token);

                return result.toString();
            }
            else
            {
                _handleException(_NAME + " ERROR en la respuesta JSON: " + response.toString());
            }
        }
        catch (ParseException e) {_handleException(_NAME + " ERROR en la respuesta JSON!!", e);}
        catch (IOException e)    {_handleException(_NAME + " ERROR solicitando token de acceso!!", e);}
        finally
        {
            _closeResources(reader, httpClient);
        }

        return null;
    }

    /**
     *
     * @param reader
     * @param httpClient
     */
    private void _closeResources(final BufferedReader reader, final CloseableHttpClient httpClient) {
        if (reader != null) IOUtils.closeQuietly(reader);

        try
        {
            if (httpClient != null) httpClient.close();
        }
        catch (IOException e)
        {
            log.error(e);
        }
    }

    /**
     *
     * @param msg
     */
    private void _handleException(final String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     *
     * @param msg
     * @param e
     */
    private void _handleException(final String msg, final Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    /**
     *
     * @param clientId
     * @param clientSecret
     * @return
     * @throws APIManagementException
     */
    private String _getCredentials(final String clientId, final String clientSecret) throws APIManagementException {
        final StringBuilder result = new StringBuilder();

        result.append(clientId).append(":").append(clientSecret);

        try
        {
            return Base64.getEncoder().encodeToString(result.toString().getBytes(Constantes.UTF_8));
        }
        catch(UnsupportedEncodingException e)
        {
            throw new APIManagementException(_NAME + " ERROR metodo de encoding no soportado!!", e);
        }
    }

    /**
     *
     * @param reader
     * @return
     * @throws ParseException
     * @throws IOException
     */
    private JSONObject _getParsedObjectByReader(final BufferedReader reader) throws ParseException, IOException {
        return (reader != null) ? (JSONObject) new JSONParser().parse(reader) : null;
    }

    /**
     * Update the access token info after getting new access token.
     *
     * @param result    Token info need to be updated.
     * @param responseJSON AccessTokenInfo
     * @return AccessTokenInfo
     */
    private AccessTokenInfo _updateTokenInfo(final AccessTokenInfo result, final JSONObject responseJSON) {
        //1.- Access token
        result.setAccessToken((String) responseJSON.get("access_token"));

        //2.- Expires in
        final Long expireTime = (Long) responseJSON.get("expires_in");
        if (expireTime == null)
        {
            result.setTokenValid(false);
            result.setErrorcode (APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);
            return result;
        }
        result.setValidityPeriod(expireTime * 1000);

        //3.- Scopes
        final String tokenScopes = (String) responseJSON.get("scope");
        if (StringUtils.isNotEmpty(tokenScopes)) result.setScope(tokenScopes.split("\\s+"));

        //4.- Token valid
        result.setTokenValid(Boolean.parseBoolean("active"));
        result.setTokenState("active");

        //5.- Fin
        return result;
    }

    /**
     * Revokes an access token.
     *
     * @param clientId     clientId of the oauth client
     * @param clientSecret clientSecret of the oauth client
     * @param accessToken  token being revoked
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private void _revokeAccessToken(final String clientId, final String clientSecret, final String accessToken) throws APIManagementException {
        //TODO
    }

    /**
     * Gets an access token.
     *
     * @param clientId     clientId of the oauth client.
     * @param clientSecret clientSecret of the oauth client.
     * @param parameters   list of request parameters.
     * @return an {@code JSONObject}
     * @throws APIManagementException This is the custom exception class for API management.
     */
    private JSONObject _getAccessToken(final String clientId, final String clientSecret, final List<NameValuePair> parameters) throws APIManagementException {
        final CloseableHttpClient httpClient = HttpClientBuilder.create().build();
        BufferedReader            reader     = null;

        try
        {
            final HttpPost post = new HttpPost(Constantes.Properties2.KEYCLOAK_TOKEN_ENDPOINT);

            post.setEntity(new UrlEncodedFormEntity(parameters));
            post.setHeader(Constantes.HTTP_HEADER_AUTH, Constantes.HTTP_HEADER_AUTH_BASIC + _getCredentials(clientId, clientSecret));

            final HttpResponse response   = httpClient.execute(post);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            if (entity == null)
            {
                _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth:" + String.valueOf(response));
            }

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), Constantes.UTF_8));

            final JSONObject result = _getParsedObjectByReader(reader);

            if (HttpStatus.SC_OK == statusCode)
            {
                return result;
            }
            else
            {
                _handleException(_NAME + " ERROR obteniendo un token de acceso para: " + clientId);
            }
        }
        catch (UnsupportedEncodingException e) {_handleException(_NAME + " ERROR encoding no soportado!!", e);}
        catch (ParseException               e) {_handleException(_NAME + " ERROR parseando la respuesta JSON!!", e);}
        catch (IOException                  e) {_handleException(_NAME + " ERROR enviando peticion al servidor OAuth!!", e);}
        finally
        {
            _closeResources(reader, httpClient);
        }

        return null;
    }

    /**
     * Convierte un tipo OAuthApplicationInfo a partir de la INFO recibida de Keycloak.
     *
     * @param x Mapa con los atributos devueltos por Keycloak
     * @return
     */
    private OAuthApplicationInfo _createOAuthAppInfoFromResponseOld(final Map x) {
        final OAuthApplicationInfo result     = new OAuthApplicationInfo();
        final String               clientName = (String) x.get(Constantes.KEYCLOAK.CLIENT_ID);

        log.error(_NAME + "._createOAuthAppInfoFromResponseOld(" + x + ")");

        result.setClientName  (clientName);
        result.setClientId    ((String) x.get(Constantes.KEYCLOAK.CLIENT_ID));
        result.setClientSecret((String) x.get(Constantes.KEYCLOAK.CLIENT_SECRET));

        final JSONArray callbackUrl = (JSONArray) x.get(Constantes.KEYCLOAK.REDIRECT_URIS);
        if (callbackUrl != null)
        {
            result.setCallBackURL((String) callbackUrl.toArray()[0]);
        }

        return result;
    }

    /**
     * Convierte un tipo OAuthApplicationInfo a partir de la INFO recibida de Keycloak.
     *
     * @param x Mapa con los atributos devueltos por Keycloak
     * @return
     */
    private OAuthApplicationInfo _createOAuthAppInfoFromResponse(final Map x, final OAuthApplicationInfo inicial) {
        final OAuthApplicationInfo result   = new OAuthApplicationInfo();
        final String               clientId = (String) x.get(Constantes.KEYCLOAK.OIDC_CLIENT_ID);

        log.error(_NAME + "._createOAuthAppInfoFromResponse(" + x + ")");

        //1.- Inicia el objeto a los valores previos
        if (inicial != null) _inicia(inicial, result);

        //2.- Client id and secret
        result.setClientId    (clientId);
        result.setClientName  ((String) x.get(Constantes.KEYCLOAK.OIDC_CLIENT_NAME));
        result.setClientSecret((String) x.get(Constantes.KEYCLOAK.OIDC_CLIENT_SECRET));

        //3.- Redirect URIs
        final JSONArray callbackUrl = (JSONArray) x.get(Constantes.KEYCLOAK.OIDC_REDIRECT_URIS);
        if (callbackUrl != null)
        {
            result.setCallBackURL((String) callbackUrl.toArray()[0]);
        }

        //4.- Grant types
        final JSONArray grantTypes = (JSONArray) x.get(Constantes.KEYCLOAK.OIDC_GRANT_TYPES);
        final StringBuilder gt = new StringBuilder();
        for (Object type : grantTypes)
        {
            gt.append(type).append(Constantes.SPACE);
        }
        result.addParameter(Constantes.WSO2APIM.CLIENT_GRANT_TYPES, gt.toString());

        //5.- Other parameters
        result.addParameter(Constantes.WSO2APIM.CLIENT_SECRET_EXPIRES_AT,          x.get(Constantes.KEYCLOAK.OIDC_CLIENT_SECRET_EXPIRES_AT));
        result.addParameter(Constantes.WSO2APIM.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD, x.get(Constantes.KEYCLOAK.OIDC_TOKEN_ENDPOINT_AUTH_METHOD));

        //6.- Fin
        return result;
    }

    /**
     * Crea la petición a Keycloak a partir de la info recibida en el objeto OAuthApplicationInfo
     *
     * @param oAuthApplicationInfo
     * @return
     * @throws APIManagementException
     */
    private String _createJsonPayloadFromOauthApplicationOld(OAuthApplicationInfo oAuthApplicationInfo) throws APIManagementException {
        final Map<String, Object> result = new HashMap<String, Object>();

        //Client Name
        final String clientName = oAuthApplicationInfo.getClientName();
        if (StringUtils.isNotEmpty(clientName)) result.put(Constantes.KEYCLOAK.CLIENT_ID, clientName);

        //Redirect URIs
        final String clientRedirectUri = oAuthApplicationInfo.getCallBackURL();
        if (StringUtils.isNotEmpty(clientRedirectUri))
        {
            final List<String> redirectUris = Collections.singletonList(clientRedirectUri);
            result.put(Constantes.KEYCLOAK.REDIRECT_URIS, redirectUris);
        }

        return JSONObject.toJSONString(result);
    }

    /**
     * Crea la petición a Keycloak a partir de la info recibida en el objeto OAuthApplicationInfo
     *
     * @param oAuthApplicationInfo
     * @return
     * @throws APIManagementException
     */
    private String _createJsonPayloadFromOauthApplication(OAuthApplicationInfo oAuthApplicationInfo) throws APIManagementException {
        final Map<String, Object> result = new HashMap<String, Object>();

        //Client Name
        final String client_id = oAuthApplicationInfo.getClientId();
        if (StringUtils.isNotEmpty(client_id)) result.put(Constantes.KEYCLOAK.OIDC_CLIENT_ID, client_id);

        //Client Name
        final String client_name = oAuthApplicationInfo.getClientName();
        if (StringUtils.isNotEmpty(client_name)) result.put(Constantes.KEYCLOAK.OIDC_CLIENT_NAME, client_name);

        //Client Secret
        final String client_secret = oAuthApplicationInfo.getClientSecret();
        if (StringUtils.isNotEmpty(client_name)) result.put(Constantes.KEYCLOAK.OIDC_CLIENT_SECRET, client_secret);

        //Redirect URIs
        final String clientRedirectUri = oAuthApplicationInfo.getCallBackURL();
        if (StringUtils.isNotEmpty(clientRedirectUri))
        {
            final List<String> redirect_uris = Collections.singletonList(clientRedirectUri);
            result.put(Constantes.KEYCLOAK.OIDC_REDIRECT_URIS, redirect_uris);
        }

        //Response Types
        final Object clientResponseTypes = oAuthApplicationInfo.getParameter(Constantes.WSO2APIM.CLIENT_RESPONSE_TYPES);
        if (clientResponseTypes != null)
        {
            final String[]  responseTypes = ((String) clientResponseTypes).split(",");
            final JSONArray jsonArray     = new JSONArray();
            Collections.addAll(jsonArray, responseTypes);
            result.put(Constantes.KEYCLOAK.OIDC_RESPONSE_TYPES, jsonArray);
        }

        //Grant Types
        final Object clientGrantTypes = oAuthApplicationInfo.getParameter(Constantes.WSO2APIM.CLIENT_GRANT_TYPES);
        if (clientGrantTypes != null)
        {
            final String[]  grantTypes = ((String) clientGrantTypes).split(",");
            final JSONArray jsonArray  = new JSONArray();
            Collections.addAll(jsonArray, grantTypes);
            result.put(Constantes.KEYCLOAK.OIDC_GRANT_TYPES, jsonArray);
        }

        // Logout Redirect URI
//        final Object clientPostLogoutRedirectUris = oAuthApplicationInfo.getParameter(Constantes.CLIENT_POST_LOGOUT_REDIRECT_URIS);
//        if (clientPostLogoutRedirectUris != null)
//        {
//            final String[]  postLogoutRedirectUris = ((String) clientPostLogoutRedirectUris).split(",");
//            final JSONArray jsonArray = new JSONArray();
//            Collections.addAll(jsonArray, postLogoutRedirectUris);
//        }

        //Token endpoint AUTH Method
//        final String tokenEndpointAuthMethod = (String) oAuthApplicationInfo.getParameter(Constantes.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD);

        //Client URI
//        final String clientUri = (String) oAuthApplicationInfo.getParameter(Constantes.CLIENT_URI);

        //Client Logo URI
//        final String logoUri = (String) oAuthApplicationInfo.getParameter(Constantes.CLIENT_LOGO_URI);

        //Client Initiate Login URI
//        final String initiateLoginUri = (String) oAuthApplicationInfo.getParameter(Constantes.CLIENT_INITIATE_LOGIN_URI);

        //Client Application Type
//        final String applicationType = (String) oAuthApplicationInfo.getParameter(Constantes.CLIENT_APPLICATION_TYPE);

        return JSONObject.toJSONString(result);
    }

    /*-------------------------------------------------------------------------*/
    /*                Metodos publicos                                         */
    /*-------------------------------------------------------------------------*/
    /**
     * Creates a new OAuth application in the Authorization Server.
     * curl -X POST
     *      -d '{"clientId":"myclient"}'
     *      -H "Content-Type:application/json"
     *      -H "Authorization: Basic YWRtaW46cGFzc3dvcmQK"
     *      https://idp.keycloak.local:8443/auth/realms/master/clients-registrations/default
     *
     * @param req
     * @return
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo createApplication(final OAuthAppRequest req) throws APIManagementException {
        BufferedReader reader = null;

        log.warn(_NAME + ".createApplication()");

        final OAuthApplicationInfo oAuthApplicationInfo = req.getOAuthApplicationInfo();
        final String[]             scope                = ((String) oAuthApplicationInfo.getParameter(Constantes.WSO2APIM.TOKEN_SCOPE)).split(",");
        final Object               tokenGrantType       =           oAuthApplicationInfo.getParameter(Constantes.WSO2APIM.TOKEN_GRANT_TYPE);
        final String               registrationEndpoint = Constantes.Properties2.CLIENT_REG_ENDPOINT;

        final CloseableHttpClient httpClient = HttpClientBuilder.create().build();

        try
        {
            final String   payload = _createJsonPayloadFromOauthApplicationOld(oAuthApplicationInfo);
            final HttpPost post    = new HttpPost(registrationEndpoint);

            post.setEntity(new StringEntity(payload, Constantes.UTF_8));

            post.setHeader(Constantes.HTTP_HEADER_CONTENT_TYPE, Constantes.HTTP_HEADER_CT_APPLICATION_JSON);
            post.setHeader(Constantes.HTTP_HEADER_AUTH,         _getAuthorization());

            final HttpResponse response   = httpClient.execute(post);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            if (entity == null)
            {
                _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth:" + String.valueOf(response));
            }

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), Constantes.UTF_8));

            final JSONObject jsonResponse = _getParsedObjectByReader(reader);
            if (jsonResponse == null)
            {
                _handleException(_NAME + " ERROR parseando la respuesta JSON!!");
            }

            log.error(_NAME + " jsonResponse: " + jsonResponse.toJSONString());

            if (HttpStatus.SC_CREATED == statusCode)
            {
                final OAuthApplicationInfo result = _createOAuthAppInfoFromResponseOld(jsonResponse);

                result.addParameter(Constantes.WSO2APIM.TOKEN_SCOPE,      scope);
                result.addParameter(Constantes.WSO2APIM.TOKEN_GRANT_TYPE, tokenGrantType);

                return result;
            }
            else
            {
                _handleException(_NAME + " ERROR registrando un nuevo cliente en el servidor OAuth. Response: " + jsonResponse.toJSONString());
            }
        }
        catch (ParseException e) {_handleException(_NAME + " ERROR parseando la respuesta JSON!!", e);}
        catch (IOException e)    {_handleException(_NAME + " ERROR enviando peticion al servidor OAuth!!", e);}
        finally
        {
            _closeResources(reader, httpClient);
        }
        return null;
    }

    /**
     *
     * @param kmc
     * @throws APIManagementException
     */
    @Override
    public void loadConfiguration(final KeyManagerConfiguration kmc) throws APIManagementException {
        this.configuration = kmc;
    }

    /**
     * Get Scopes of the APIs by API Ids
     * @param x
     * @return
     * @throws APIManagementException
     */
    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(final String x) throws APIManagementException {
        return new HashMap<>();
    }

    /**
     * Obtiene la informacion de una aplicacion a partir de su clientId.
     * curl -k -X GET
     *      -H "Authorization: Bearer XXXXX"
     *      https://idp.keycloak.local:8443/auth/realms/master/clients-registrations/openid-connect/clientId
     *
     * @param clientId
     * @return
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(final String clientId) throws APIManagementException {
        BufferedReader reader = null;

        log.error(_NAME + ".retrieveApplication(" + clientId + ")");

        final CloseableHttpClient httpClient = HttpClientBuilder.create().build();

        try
        {
            final HttpGet request = new HttpGet(Constantes.Properties2.KEYCLOAK_ENDPOINT + Constantes.URL_SEPARATOR + clientId);

            request.addHeader(Constantes.HTTP_HEADER_AUTH, _getAuthorization());

            final HttpResponse response   = httpClient.execute(request);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            log.error(_NAME + " response: " + response.toString());

            if (entity == null)
            {
                _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth (" + clientId + "): " + String.valueOf(response));
            }

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), Constantes.UTF_8));

            final JSONObject jsonResponse = _getParsedObjectByReader(reader);
            if (jsonResponse == null)
            {
                _handleException(_NAME + " ERROR parseando la respuesta JSON!!");
            }

            log.error(_NAME + " jsonResponse: " + jsonResponse.toJSONString());

            if (statusCode == HttpStatus.SC_OK)
            {
                return _createOAuthAppInfoFromResponse(jsonResponse, null);
            }
            else
            {
                _handleException(String.format("Error occured while retrieving client for the Consumer Key %s", clientId));
            }
        }
        catch (ParseException e) {_handleException(_NAME + " ERROR parseando la respuesta JSON (" + clientId + ")!!", e);}
        catch (IOException e)    {_handleException(_NAME + " ERROR recuperando info de la aplicacion" + clientId + "!!", e);}
        finally
        {
            _closeResources(reader, httpClient);
        }

        return null;
    }

    /**
     * Provides details of the Access Token that is displayed on the Store.
     *
     * @param clientId
     * @return
     * @throws APIManagementException
     */
    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(final String clientId) throws APIManagementException {
        final AccessTokenInfo result = null;

        log.error(_NAME + ".getAccessTokenByConsumerKey(" + clientId + ")");

        return null;
    }

    /**
     * Updates an OAuth application.
     *
     * @param req
     * @return
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo updateApplication(final OAuthAppRequest req) throws APIManagementException {
        BufferedReader reader = null;

        log.error(_NAME + ".updateApplication()");

        final OAuthApplicationInfo oAuthApplicationInfo = req.getOAuthApplicationInfo();
        final CloseableHttpClient  httpClient           = HttpClientBuilder.create().build();
        final String               clientId             = oAuthApplicationInfo.getClientId();

        log.error(_NAME + ".updateApplication: " + Constantes.view(oAuthApplicationInfo));

        try
        {
            final String  payload = _createJsonPayloadFromOauthApplication(oAuthApplicationInfo);
            final HttpPut put     = new HttpPut(Constantes.Properties2.KEYCLOAK_ENDPOINT + Constantes.URL_SEPARATOR + clientId);

            put.setEntity(new StringEntity(payload, Constantes.UTF_8));

            put.setHeader(Constantes.HTTP_HEADER_CONTENT_TYPE, Constantes.HTTP_HEADER_CT_APPLICATION_JSON);
            put.setHeader(Constantes.HTTP_HEADER_AUTH,         _getAuthorization());

            final HttpResponse response   = httpClient.execute(put);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            log.error(_NAME + " response: " + response.toString());

            if (entity == null)
            {
                _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth (" + clientId + "): " + String.valueOf(response));
            }

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), Constantes.UTF_8));

            final JSONObject jsonResponse = _getParsedObjectByReader(reader);
            if (jsonResponse == null)
            {
                _handleException(_NAME + " ERROR parseando la respuesta JSON!!");
            }

            log.error(_NAME + " jsonResponse: " + jsonResponse.toJSONString());

            if (statusCode == HttpStatus.SC_OK)
            {
                return _createOAuthAppInfoFromResponse(jsonResponse, oAuthApplicationInfo);
            }
            else
            {
                _handleException(String.format("Error occured while retrieving client for the Consumer Key %s", clientId));
            }
        }
        catch (ParseException e) {_handleException(_NAME + " ERROR parseando la respuesta JSON (" + clientId + ")!!", e);}
        catch (IOException e)    {_handleException(_NAME + " ERROR recuperando info de la aplicacion" + clientId + "!!", e);}
        finally
        {
            _closeResources(reader, httpClient);
        }

        return null;
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param clientId
     * @throws APIManagementException
     */
    @Override
    public void deleteApplication(final String clientId) throws APIManagementException {
        BufferedReader reader = null;

        log.error(_NAME + ".deleteApplication(" + clientId + ")");

        final CloseableHttpClient httpClient = HttpClientBuilder.create().build();

        try
        {
            final HttpDelete delete = new HttpDelete(Constantes.Properties2.KEYCLOAK_ENDPOINT + Constantes.URL_SEPARATOR + clientId);

            delete.addHeader(Constantes.HTTP_HEADER_AUTH, _getAuthorization());

            final HttpResponse response   = httpClient.execute(delete);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            log.error(_NAME + " response: " + response.toString());

            if (statusCode != HttpStatus.SC_NO_CONTENT)
            {
                if (entity == null) _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth (" + clientId + "): " + String.valueOf(response));

                reader = new BufferedReader(new InputStreamReader(entity.getContent(), Constantes.UTF_8));
                final JSONObject jsonResponse = _getParsedObjectByReader(reader);

                _handleException(_NAME + "ERROR borrando el cliente (" + clientId + ") Response :" + jsonResponse.toJSONString());
            }
        }
        catch (ParseException e) {_handleException(_NAME + " ERROR parseando la respuesta JSON (" + clientId + ")!!", e);}
        catch (IOException e)    {_handleException(_NAME + " ERROR recuperando info de la aplicacion" + clientId + "!!", e);}
        finally
        {
            _closeResources(reader, httpClient);
        }
    }

    /**
     * Deletes mapping records of oAuth applications.
     *
     * @param clientId
     * @throws APIManagementException
     */
    @Override
    public void deleteMappedApplication(final String clientId) throws APIManagementException {
        log.error(_NAME + ".deleteMappedApplication(" + clientId + ")");
    }

    /**
     * Provides all the Active tokens issued against the provided Consumer Key.
     *
     * @param clientId
     * @return
     * @throws APIManagementException
     */
    @Override
    public Set<String> getActiveTokensByConsumerKey(final String clientId) throws APIManagementException {
        log.error(_NAME + ".getActiveTokensByConsumerKey(" + clientId + ")");

        return Collections.emptySet();
    }

    /**
     * Gets new access token and returns it in an AccessTokenInfo object.
     *
     * @param x Info of the token needed.
     * @return AccessTokenInfo Info of the new token.
     * @throws APIManagementException This is the custom exception class for API management.
     */
    @Override
    public AccessTokenInfo getNewApplicationAccessToken(final AccessTokenRequest x) throws APIManagementException {
        final AccessTokenInfo result = new AccessTokenInfo();

        log.error(_NAME + ".getNewApplicationAccessToken()");

        //1.- Get info data
        final String accessToken  = x.getTokenToRevoke();
        final String clientId     = x.getClientId();
        final String clientSecret = x.getClientSecret();

        //2.- Revoke access token
        if (StringUtils.isNotEmpty(accessToken)) _revokeAccessToken(clientId, clientSecret, accessToken);

        //3.- Grant type
        List<NameValuePair> parameters = new ArrayList<NameValuePair>();
        String grantType = x.getGrantType();
        if (grantType == null) grantType = "client_credentials";

        parameters.add(new BasicNameValuePair("grant_type", (String) grantType));

        //4.- Scopes
        final String scopes = _convertToString(x.getScope());
        if (StringUtils.isNotEmpty(scopes)) parameters.add(new BasicNameValuePair("scope", scopes));

        //5.- Update info
        JSONObject responseJSON = _getAccessToken(clientId, clientSecret, parameters);
        if (responseJSON != null)
        {
            _updateTokenInfo(result, responseJSON);
        }
        else
        {
            result.setTokenValid(false);
            result.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_INVALID_CREDENTIALS);

            log.info(_NAME + "OAuth token validation failed for the Consumer Key " + clientId);
        }

        //7.- Fin
        return result;
    }

    /**
     *
     * @return
     * @throws APIManagementException
     */
    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    /**
     *
     * @param x
     * @return
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo buildFromJSON(final String x) throws APIManagementException {
        log.error(_NAME + ".buildFromJSON(" + x + ")");

        return null;
    }

    /**
     *
     * @param oaar
     * @return
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(final OAuthAppRequest oaar) throws APIManagementException {
        log.error(_NAME + ".mapOAuthApplication()");

        return oaar.getOAuthApplicationInfo();
    }

    /**
     *
     * @param api
     * @param map
     * @return
     * @throws APIManagementException
     */
    @Override
    public boolean registerNewResource(final API api, final Map map) throws APIManagementException {
        log.error(_NAME + ".registerNewResource()");

        return true;
    }

    /**
     *
     * @param x
     * @return
     * @throws APIManagementException
     */
    @Override
    public Map getResourceByApiId(final String x) throws APIManagementException {
        log.error(_NAME + ".getResourceByApiId(" + x + ")");

        return null;
    }

    /**
     *
     * @param api
     * @param map
     * @return
     * @throws APIManagementException
     */
    @Override
    public boolean updateRegisteredResource(final API api, final Map map) throws APIManagementException {
        log.error(_NAME + ".updateRegisteredResource()");

        return true;
    }

    /**
     *
     * @param x
     * @throws APIManagementException
     */
    @Override
    public void deleteRegisteredResourceByAPIId(final String x) throws APIManagementException {
        log.error(_NAME + ".deleteRegisteredResourceByAPIId(" + x + ")");
    }



    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest atr) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
