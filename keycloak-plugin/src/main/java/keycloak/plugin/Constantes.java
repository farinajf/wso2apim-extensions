/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package keycloak.plugin;

import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;

/**
 *
 * @author fran
 */
public final class Constantes {
    public static final String HTTP_HEADER_AUTH                  = "Authorization";
    public static final String HTTP_HEADER_AUTH_BASIC            = "Basic ";
    public static final String HTTP_HEADER_AUTH_BEARER           = "Bearer ";
    public static final String HTTP_HEADER_CONTENT_TYPE          = "Content-Type";
    public static final String HTTP_HEADER_CT_APPLICATION_JSON   = "application/json";
    public static final String HTTP_HEADER_CT_FORM_URL_ENCODED   = "application/x-www-form-urlencoded";
    public static final String SPACE                             = " ";
    public static final String UTF_8                             = "UTF-8";
    public static final String URL_SEPARATOR                     = "/";

    /**
     * Atributos especificos de Keycloak
     */
    public static final class KEYCLOAK {
        public static final String ACCESS_TOKEN                    = "access_token";
        public static final String CLIENT_ID                       = "clientId";
        public static final String CLIENT_SECRET                   = "secret";
        public static final String REDIRECT_URIS                   = "redirectUris";

        public static final String OIDC_CLIENT_ID                  = "client_id";
        public static final String OIDC_CLIENT_NAME                = "client_name";
        public static final String OIDC_CLIENT_SECRET              = "client_secret";
        public static final String OIDC_CLIENT_SECRET_EXPIRES_AT   = "client_secret_expires_at";
        public static final String OIDC_GRANT_TYPES                = "grant_types";
        public static final String OIDC_REDIRECT_URIS              = "redirect_uris";
        public static final String OIDC_RESPONSE_TYPES             = "response_types";
        public static final String OIDC_TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
    }

    /**
     * Atributos definidos en WSO2APIM.
     */
    public static final class WSO2APIM {
        public static final String CLIENT_APPLICATION_TYPE           = "application_type";
        public static final String CLIENT_ID_ISSUED_AT               = "client_id_issued_at";
        public static final String CLIENT_GRANT_TYPES                = "grant_types";
        public static final String CLIENT_INITIATE_LOGIN_URI         = "initiate_login_uri";
        public static final String CLIENT_LOGO_URI                   = "logo_uri";
        public static final String CLIENT_POST_LOGOUT_REDIRECT_URIS  = "post_logout_redirect_uris";
        public static final String CLIENT_RESPONSE_TYPES             = "response_types";
        public static final String CLIENT_SECRET_EXPIRES_AT          = "client_secret_expires_at";
        public static final String CLIENT_TOKEN_ENDPOINT_AUTH_METHOD = "token_endpoint_auth_method";
        public static final String CLIENT_URI                        = "client_uri";
        public static final String TOKEN_GRANT_TYPE                  = "tokenGrantType";
        public static final String TOKEN_SCOPE                       = "tokenScope";
    }

    /**
     *
     */
    public static class Properties2 {
        public static final String ACCESS_TOKEN_ENDPOINT    = "https://idp.keycloak.local:8443/auth/realms/master/protocol/openid-connect/token";
        public static final String CLIENT_ID                = "wso2apim";
        public static final String CLIENT_SECRET            = "3f5cbc5a-e70e-4e24-944b-256f0f9d32c7";
        public static final String USERNAME                 = "admin";
        public static final String PASSWORD                 = "password";
        public static final String CLIENT_REG_ENDPOINT      = "https://idp.keycloak.local:8443/auth/realms/master/clients-registrations/default";
        public static final String KEYCLOAK_ENDPOINT        = "https://idp.keycloak.local:8443/auth/realms/master/clients-registrations/openid-connect";
        public static final String KEYCLOAK_TOKEN_ENDPOINT  = "https://idp.keycloak.local:8443/auth/realms/master/protocol/openid-connect/token";
        public static final String KEYCLOAK_LOGOUT_ENDPOINT = "https://idp.keycloak.local:8443/auth/realms/master/protocol/openid-connect/logout";
    }

    public static final String view(final OAuthApplicationInfo x) {
        final StringBuilder result = new StringBuilder();

        result.append("CLIENT_ID:").append(x.getClientId()).append('|');
        result.append("CLIENT_NAME:").append(x.getClientName()).append('|');
        result.append("CLIENT_SECRET:").append(x.getClientSecret()).append('|');
        result.append("CALLBACK_URLS:").append(x.getCallBackURL()).append('|');
        result.append("TOKEN_TYPE:").append(x.getTokenType()).append('|');
        result.append("JSON_APP_ATRIBUTE:").append(x.getJsonAppAttribute()).append('|');
        result.append("JSON_STIRNG:").append(x.getJsonString()).append('|');

        return result.toString();
    }
}
