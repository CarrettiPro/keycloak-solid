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
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.PreAuthorizationRequestContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.util.JsonSerialization;

public class SolidClientRegistrationExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    private final Logger LOG = Logger.getLogger(SolidClientRegistrationExecutor.class);

    private final KeycloakSession session;

    public SolidClientRegistrationExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        if (context.getEvent() == ClientPolicyEvent.PRE_AUTHORIZATION_REQUEST) {
            registerSolidClient((PreAuthorizationRequestContext) context);
        }
    }

    @Override
    public String getProviderId() {
        return SolidClientRegistrationExecutorFactory.PROVIDER_ID;
    }

    private void registerSolidClient(PreAuthorizationRequestContext context) {
        ClientModel client;
        String clientId = context.getClientId();
        RealmModel realm = session.getContext().getRealm();
        client = realm.getClientByClientId(clientId);

        if (client == null) {
            try {
                HttpClient httpClient = session.getProvider(HttpClientProvider.class).getHttpClient();
                HttpGet request = new HttpGet(new URI(clientId));
                HttpResponse response = httpClient.execute(request);
                HttpEntity entity = response.getEntity();
                if (entity == null) {
                    LOG.warnv("{0} didn't resolve to a HTTP entity", clientId);
                    return;
                }

                SolidClientIDDocument doc = JsonSerialization.readValue(entity.getContent(), SolidClientIDDocument.class);

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
                config.setDPoPEnabled(true);

            } catch (IOException ex) {
                LOG.warnv("Could not fetch client ID document from {0}", clientId);
            } catch (URISyntaxException ex) {
                LOG.warnv("{0} is not a valid URI, ignoring", ex);
            }
        } else {
            LOG.debugv("Client {0} already exists, ignoring", clientId);
        }
    }

}
