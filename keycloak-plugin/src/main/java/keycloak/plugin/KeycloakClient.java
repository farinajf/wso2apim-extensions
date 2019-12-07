/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package keycloak.plugin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
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
    private String _getAuthorization() throws APIManagementException {
        final StringBuilder result = new StringBuilder();
        BufferedReader      reader = null;

        log.info(_NAME + "._getAuthorization()");

        final String              accessTokenEndpoint = KeycloakClientConstants.Properties2.ACCESS_TOKEN_ENDPOINT;
        final CloseableHttpClient httpClient          = HttpClientBuilder.create().build();

        try
        {
            final StringBuilder payload = new StringBuilder();
            final HttpPost      post    = new HttpPost(accessTokenEndpoint);

            payload.append("username=").append (KeycloakClientConstants.Properties2.USERNAME);
            payload.append("&password=").append(KeycloakClientConstants.Properties2.PASSWORD);
            payload.append("&grant_type=password");
            payload.append("&client_id=").append    (KeycloakClientConstants.Properties2.CLIENT_ID);
            payload.append("&client_secret=").append(KeycloakClientConstants.Properties2.CLIENT_SECRET);

            post.setEntity(new StringEntity(payload.toString(), KeycloakClientConstants.UTF_8));
            post.setHeader(KeycloakClientConstants.HTTP_HEADER_CONTENT_TYPE, KeycloakClientConstants.CT_FORM_URL_ENCODED);

            final HttpResponse response   = httpClient.execute(post);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            log.info(_NAME + " response: " + response.toString());

            if (entity == null)
            {
                _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth: " + String.valueOf(response));
            }

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeycloakClientConstants.UTF_8));

            if (statusCode == HttpStatus.SC_OK)
            {
                final JSONObject jsonResponse = _getParsedObjectByReader(reader);
                log.info(_NAME + " jsonResponse: " + jsonResponse.toJSONString());

                final String access_token = (String) jsonResponse.get(KeycloakClientConstants.TOKEN_ACCESS_TOKEN);

                result.append(KeycloakClientConstants.AUTHENTICATION_BEARER).append(" ").append(access_token);

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
     * @return
     */
    private String _getCredentials() {
        final StringBuilder result = new StringBuilder();

        result.append(KeycloakClientConstants.Properties2.CLIENT_ID);
        result.append(":");
        result.append(KeycloakClientConstants.Properties2.CLIENT_SECRET);

        return Base64.getEncoder().encodeToString(result.toString().getBytes());
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
     *
     * @param x
     * @return
     */
    private OAuthApplicationInfo _createOAuthAppInfoFromResponse(final Map x) {
        final OAuthApplicationInfo result     = new OAuthApplicationInfo();
        final String               clientName = (String) x.get(KeycloakClientConstants.CLIENT_NAME);

        result.setClientName  (clientName);
        result.setClientId    ((String) x.get(KeycloakClientConstants.CLIENT_ID));
        result.setClientSecret((String) x.get(KeycloakClientConstants.CLIENT_SECRET));

        final JSONArray callbackUrl = (JSONArray) x.get(KeycloakClientConstants.CLIENT_REDIRECT_URIS);
        if (callbackUrl != null)
        {
            result.setCallBackURL((String) callbackUrl.toArray()[0]);
        }

        result.addParameter(KeycloakClientConstants.CLIENT_ID_ISSUED_AT,               x.get(KeycloakClientConstants.CLIENT_ID_ISSUED_AT));
        result.addParameter(KeycloakClientConstants.CLIENT_SECRET_EXPIRES_AT,          x.get(KeycloakClientConstants.CLIENT_SECRET_EXPIRES_AT));
        result.addParameter(KeycloakClientConstants.CLIENT_URI,                        x.get(KeycloakClientConstants.CLIENT_URI));
        result.addParameter(KeycloakClientConstants.CLIENT_LOGO_URI,                   x.get(KeycloakClientConstants.CLIENT_LOGO_URI));
        result.addParameter(KeycloakClientConstants.CLIENT_APPLICATION_TYPE,           x.get(KeycloakClientConstants.CLIENT_APPLICATION_TYPE));
        result.addParameter(KeycloakClientConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS,  x.get(KeycloakClientConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS));
        result.addParameter(KeycloakClientConstants.CLIENT_RESPONSE_TYPES,             x.get(KeycloakClientConstants.CLIENT_RESPONSE_TYPES));
        result.addParameter(KeycloakClientConstants.CLIENT_GRANT_TYPES,                x.get(KeycloakClientConstants.CLIENT_GRANT_TYPES));
        result.addParameter(KeycloakClientConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD, x.get(KeycloakClientConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD));
        result.addParameter(KeycloakClientConstants.CLIENT_INITIATE_LOGIN_URI,         x.get(KeycloakClientConstants.CLIENT_INITIATE_LOGIN_URI));

        return result;
    }

    /**
     *
     * @param oAuthApplicationInfo
     * @return
     * @throws APIManagementException
     */
    private String _createJsonPayloadFromOauthApplication(OAuthApplicationInfo oAuthApplicationInfo) throws APIManagementException {
        final Map<String, Object> result = new HashMap<String, Object>();

        //Client Name
        final String clientName = oAuthApplicationInfo.getClientName();
        if (StringUtils.isNotEmpty(clientName)) result.put(KeycloakClientConstants.CLIENT_KEYCLOAK_NAME, clientName);

        //Redirect URIs
        final String clientRedirectUri = oAuthApplicationInfo.getCallBackURL();
        if (StringUtils.isNotEmpty(clientRedirectUri))
        {
            final List<String> redirectUris = Collections.singletonList(clientRedirectUri);
            result.put(KeycloakClientConstants.CLIENT_KEYCLOAK_REDIRECT_URIS, redirectUris);
        }

        //Response Types
        final Object clientResponseTypes = oAuthApplicationInfo.getParameter(KeycloakClientConstants.CLIENT_RESPONSE_TYPES);
        if (clientResponseTypes != null)
        {
            final String[]  responseTypes = ((String) clientResponseTypes).split(",");
            final JSONArray jsonArray     = new JSONArray();
            Collections.addAll(jsonArray, responseTypes);
        }

        //Grant Types
        final Object clientGrantTypes = oAuthApplicationInfo.getParameter(KeycloakClientConstants.CLIENT_GRANT_TYPES);
        if (clientGrantTypes != null)
        {
            final String[]  grantTypes = ((String) clientGrantTypes).split(",");
            final JSONArray jsonArray  = new JSONArray();
            Collections.addAll(jsonArray, grantTypes);
        }

        // Logout Redirect URI
        final Object clientPostLogoutRedirectUris = oAuthApplicationInfo.getParameter(KeycloakClientConstants.CLIENT_POST_LOGOUT_REDIRECT_URIS);
        if (clientPostLogoutRedirectUris != null)
        {
            final String[]  postLogoutRedirectUris = ((String) clientPostLogoutRedirectUris).split(",");
            final JSONArray jsonArray = new JSONArray();
            Collections.addAll(jsonArray, postLogoutRedirectUris);
        }

        //Token endpoint AUTH Method
        final String tokenEndpointAuthMethod = (String) oAuthApplicationInfo.getParameter(KeycloakClientConstants.CLIENT_TOKEN_ENDPOINT_AUTH_METHOD);

        //Client URI
        final String clientUri = (String) oAuthApplicationInfo.getParameter(KeycloakClientConstants.CLIENT_URI);

        //Client Logo URI
        final String logoUri = (String) oAuthApplicationInfo.getParameter(KeycloakClientConstants.CLIENT_LOGO_URI);

        //Client Initiate Login URI
        final String initiateLoginUri = (String) oAuthApplicationInfo.getParameter(KeycloakClientConstants.CLIENT_INITIATE_LOGIN_URI);

        //Client Application Type
        final String applicationType = (String) oAuthApplicationInfo.getParameter(KeycloakClientConstants.CLIENT_APPLICATION_TYPE);

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
    public OAuthApplicationInfo createApplication(OAuthAppRequest req) throws APIManagementException {
        BufferedReader reader = null;

        log.info(_NAME + ".createApplication()");

        final OAuthApplicationInfo oAuthApplicationInfo = req.getOAuthApplicationInfo();
        final String[]             scope                = ((String) oAuthApplicationInfo.getParameter(KeycloakClientConstants.TOKEN_SCOPE)).split(",");
        final Object               tokenGrantType       =           oAuthApplicationInfo.getParameter(KeycloakClientConstants.TOKEN_GRANT_TYPE);
        final String               registrationEndpoint = KeycloakClientConstants.Properties2.CLIENT_REG_ENDPOINT;

        final CloseableHttpClient httpClient = HttpClientBuilder.create().build();

        try
        {
            final String   payload = _createJsonPayloadFromOauthApplication(oAuthApplicationInfo);
            log.info(_NAME + " payload: " + payload);
            final HttpPost post    = new HttpPost(registrationEndpoint);

            post.setEntity(new StringEntity(payload, KeycloakClientConstants.UTF_8));

            post.setHeader(KeycloakClientConstants.HTTP_HEADER_CONTENT_TYPE, KeycloakClientConstants.CT_APPLICATION_JSON);
            post.setHeader(KeycloakClientConstants.AUTHORIZATION,            _getAuthorization());

            final HttpResponse response   = httpClient.execute(post);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            log.info(_NAME + " response: " + response.toString());

            if (entity == null)
            {
                _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth:" + String.valueOf(response));
            }

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeycloakClientConstants.UTF_8));

            final JSONObject jsonResponse = _getParsedObjectByReader(reader);
            log.info(_NAME + " jsonResponse: " + jsonResponse.toJSONString());
            if (jsonResponse == null)
            {
                _handleException(_NAME + " ERROR parseando la respuesta JSON!!");
            }

            if (HttpStatus.SC_CREATED == statusCode)
            {
                final OAuthApplicationInfo result = _createOAuthAppInfoFromResponse(jsonResponse);

                result.addParameter(KeycloakClientConstants.TOKEN_SCOPE,      scope);
                result.addParameter(KeycloakClientConstants.TOKEN_GRANT_TYPE, tokenGrantType);

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
    public OAuthApplicationInfo retrieveApplication(String clientId) throws APIManagementException {
        BufferedReader reader = null;

        log.info(_NAME + ".retrieveApplication(" + clientId + ")");

        final String              clientInfoEndpoint = KeycloakClientConstants.Properties2.CLIENT_INFO_ENDPOINT;
        final CloseableHttpClient httpClient         = HttpClientBuilder.create().build();

        try
        {
            final HttpGet request = new HttpGet(clientInfoEndpoint + KeycloakClientConstants.URL_SEPARATOR + clientId);

            request.addHeader(KeycloakClientConstants.AUTHORIZATION, _getAuthorization());

            final HttpResponse response   = httpClient.execute(request);
            final HttpEntity   entity     = response.getEntity();
            int                statusCode = response.getStatusLine().getStatusCode();

            log.info(_NAME + " response: " + response.toString());

            if (entity == null)
            {
                _handleException(_NAME + " ERROR leyendo respuesta del servidor OAuth (" + clientId + "): " + String.valueOf(response));
            }

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), KeycloakClientConstants.UTF_8));

            final JSONObject jsonResponse = _getParsedObjectByReader(reader);
            log.info(_NAME + " jsonResponse: " + jsonResponse.toJSONString());
            if (jsonResponse == null)
            {
                _handleException(_NAME + " ERROR parseando la respuesta JSON!!");
            }

            if (statusCode == HttpStatus.SC_OK)
            {
                return _createOAuthAppInfoFromResponse(jsonResponse);
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

    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oaar) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void deleteApplication(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest atr) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest atr) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest oaar) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean registerNewResource(API api, Map map) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Map getResourceByApiId(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean updateRegisteredResource(API api, Map map) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void deleteMappedApplication(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String string) throws APIManagementException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
