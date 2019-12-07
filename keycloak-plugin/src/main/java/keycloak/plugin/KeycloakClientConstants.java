/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package keycloak.plugin;

/**
 *
 * @author fran
 */
public class KeycloakClientConstants {
    public static final String APPLICATION_JSON                  = "application/json";
    public static final String AUTHORIZATION                     = "Authorization";
    public static final String AUTHENTICATION_BASIC              = "Basic ";
    public static final String CLIENT_APPLICATION_TYPE           = "application_type";
    public static final String CLIENT_GRANT_TYPES                = "grant_types";
    public static final String CLIENT_ID                         = "client_id";
    public static final String CLIENT_ID_ISSUED_AT               = "client_id_issued_at";
    public static final String CLIENT_INITIATE_LOGIN_URI         = "initiate_login_uri";
    public static final String CLIENT_LOGO_URI                   = "logo_uri";
    public static final String CLIENT_NAME                       = "client_name";
    public static final String CLIENT_POST_LOGOUT_REDIRECT_URIS  = "post_logout_redirect_uris";
    public static final String CLIENT_REDIRECT_URIS              = "redirect_uris";
    public static final String CLIENT_RESPONSE_TYPES             = "response_types";
    public static final String CLIENT_SECRET                     = "client_secret";
    public static final String CLIENT_SECRET_EXPIRES_AT          = "client_secret_expires_at";
    public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
    public static final String CLIENT_URI                        = "client_uri";
    public static final String HTTP_HEADER_CONTENT_TYPE          = "Content-Type";
    public static final String TOKEN_GRANT_TYPE                  = "tokenGrantType";
    public static final String TOKEN_SCOPE                       = "tokenScope";
    public static final String UTF_8                             = "UTF-8";

    //Argumentos definidos en el API de Keycloak: https://www.keycloak.org/docs-api/6.0/rest-api/index.html
    public static final String CLIENT_KEYCLOAK_NAME              = "clientId";
    public static final String CLIENT_KEYCLOAK_REDIRECT_URIS     = "redirectUris";

    /**
     *
     */
    public static class Properties {
        public static final String CLIENT_ID           = "keycloak.apim.clientid";
        public static final String CLIENT_SECRET       = "keycloak.apim.secret";
        public static final String CLIENT_REG_ENDPOINT = "keycloak.registrationEndpoint";
    }
}
