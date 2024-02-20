package org.solidproject.keycloak.solid;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionProvider;
import org.keycloak.services.clientpolicy.condition.ClientPolicyConditionProviderFactory;

public class SolidOIDCConditionFactory implements ClientPolicyConditionProviderFactory {

    private static final String PROVIDER_ID = "solid-oidc";

    @Override
    public ClientPolicyConditionProvider create(KeycloakSession session) {
        return new SolidOIDCCondition();
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory ksf) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Solid-OIDC Client Policy Condition";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

}
