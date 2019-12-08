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
import org.apache.http.client.methods.HttpPut;
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
     * @return
     */
    private String _getCredentials() {
        final StringBuilder result = new StringBuilder();

        result.append(Constantes.Properties2.CLIENT_ID);
        result.append(":");
        result.append(Constantes.Properties2.CLIENT_SECRET);

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
            final HttpGet request = new HttpGet(Constantes.Properties2.CLIENT_INFO_ENDPOINT + Constantes.URL_SEPARATOR + clientId);

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
            final HttpPut put     = new HttpPut(Constantes.Properties2.CLIENT_PUT_ENDPOINT + Constantes.URL_SEPARATOR + clientId);

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
}
