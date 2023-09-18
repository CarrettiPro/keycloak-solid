package org.solidproject.keycloak.solid;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.jboss.logging.Logger;

import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.DynamicClientRegisterContext;
import org.keycloak.services.clientpolicy.context.DynamicClientRegisteredContext;
import org.keycloak.services.clientpolicy.context.PreAuthorizationRequestContext;
import org.keycloak.services.clientpolicy.context.TokenResponseContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.util.JsonSerialization;

public class SolidOIDCExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    private static final String SOLID_AUDIENCE = "solid";
    private static final Logger LOG = Logger.getLogger(SolidOIDCExecutor.class);

    private final KeycloakSession session;

    public SolidOIDCExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
            case PRE_AUTHORIZATION_REQUEST -> registerSolidClient((PreAuthorizationRequestContext) context);
            case REGISTER -> dynamicClientRegister((DynamicClientRegisterContext)context);
            case REGISTERED -> dynamicClientRegistered((DynamicClientRegisteredContext)context);
            case TOKEN_RESPONSE -> {
                TokenResponseContext ctx = (TokenResponseContext) context;
                addSolidAudience(ctx);
                bindIDToken(ctx);
            }

        }
    }

    @Override
    public String getProviderId() {
        return SolidOIDCExecutorFactory.PROVIDER_ID;
    }

    private void registerSolidClient(PreAuthorizationRequestContext context) throws ClientPolicyException {
        ClientModel client;
        String clientId = context.getClientId();
        RealmModel realm = session.getContext().getRealm();
        client = realm.getClientByClientId(clientId);

        if (client == null) {
            try {
                URI uri = new URI(clientId);
                String scheme = uri.getScheme();
                if (scheme == null || (!scheme.equals("http") && !scheme.equals("https"))) {
                    LOG.warnv("Not a HTTP URI: {0}", uri);
                    return;
                }

                HttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
                HttpGet request = new HttpGet(uri);
                HttpResponse response = httpClient.execute(request);
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    LOG.warnv("{0} didn't resolve to a HTTP entity", clientId);
                    return;
                }

                OIDCClientRepresentation doc = JsonSerialization.readValue(entity.getContent(), SolidOIDCClientRepresentation.class);

                LOG.debugv("Registering client {0}", clientId);
                client = session.clients().addClient(realm, clientId);

                client.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
                client.setPublicClient(true);
                client.setBearerOnly(false);
                client.setName(doc.getClientName());
                client.setRedirectUris(Set.copyOf(doc.getRedirectUris()));
                client.setWebOrigins(Set.of("+"));

                OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
                config.setPkceCodeChallengeMethod(OIDCLoginProtocol.PKCE_METHOD_S256);
                config.setUseDPoP(true);

            } catch (IOException ex) {
                LOG.warnv(ex, "Could not fetch client ID document from {0}", clientId);
                throw new ClientPolicyException(Messages.INVALID_PARAMETER, OIDCLoginProtocol.CLIENT_ID_PARAM, ex);
            } catch (URISyntaxException ex) {
                LOG.warnv("{0} is not a valid URI, ignoring", ex);
            }
        } else {
            LOG.debugv("Client {0} already exists, ignoring", clientId);
        }
    }

    private void dynamicClientRegistered(DynamicClientRegisteredContext context) {
    }

    private void dynamicClientRegister(DynamicClientRegisterContext context) {
    }

    private void addSolidAudience(TokenResponseContext context) {
        TokenManager.AccessTokenResponseBuilder builder = context.getAccessTokenResponseBuilder();

        AccessToken accessToken = builder.getAccessToken();
        if (accessToken != null) {
            accessToken.addAudience(SOLID_AUDIENCE);
        }

        IDToken idToken = builder.getIdToken();
        if (idToken != null) {
            idToken.addAudience(SOLID_AUDIENCE);
        }
    }

    private void bindIDToken(TokenResponseContext context) {
        IDToken idToken = context.getAccessTokenResponseBuilder().getIdToken();
        if (idToken != null) {
            DPoP dPoP = (DPoP) session.getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE);
            AccessToken.Confirmation confirmation = new AccessToken.Confirmation();
            LOG.debugv("Binding IDToken to key: {0}", dPoP.getThumbprint());
            confirmation.setKeyThumbprint(dPoP.getThumbprint());
            idToken.setOtherClaims("cnf", confirmation);
        }
    }

}
