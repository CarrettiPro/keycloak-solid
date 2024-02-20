package org.solidproject.keycloak.solid;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.idm.ClientPolicyConditionConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyVote;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionProvider;
import org.keycloak.services.clientpolicy.context.PreAuthorizationRequestContext;
import org.keycloak.services.clientpolicy.context.TokenResponseContext;
import org.keycloak.util.TokenUtil;

public class SolidOIDCCondition implements ClientPolicyConditionProvider<ClientPolicyConditionConfigurationRepresentation> {

    private static final String PROVIDER_ID = "solid-oidc";
    private static final String SCOPE_WEBID = "webid";
    private static final Logger LOG = Logger.getLogger(SolidOIDCCondition.class);

    @Override
    public void setupConfiguration(ClientPolicyConditionConfigurationRepresentation config) {
    }

    @Override
    public ClientPolicyVote applyPolicy(ClientPolicyContext context) throws ClientPolicyException {
        var result = switch (context) {
            case PreAuthorizationRequestContext ctx -> preAuthorization(ctx);
            case TokenResponseContext ctx -> tokenResponse(ctx);
            default -> ClientPolicyVote.ABSTAIN;
        };
        LOG.debugv("{0} {1}", context, result);
        return result;
    }

    private ClientPolicyVote preAuthorization(PreAuthorizationRequestContext ctx) {
        String scope = ctx.getRequestParameters().getFirst(OAuth2Constants.SCOPE);
        return voteSolidScope(scope);
    }

    private ClientPolicyVote tokenResponse(TokenResponseContext ctx) {
        String scope = ctx.getAccessTokenResponseBuilder().getAccessToken().getScope();
        return voteSolidScope(scope);
    }

    @Override
    public boolean isNegativeLogic() throws ClientPolicyException {
        return false;
    }

    @Override
    public String getProviderId() {
        return PROVIDER_ID;
    }

    private ClientPolicyVote voteSolidScope(String scope) {
        return TokenUtil.hasScope(scope, SCOPE_WEBID) ? ClientPolicyVote.YES : ClientPolicyVote.NO;
    }

}
