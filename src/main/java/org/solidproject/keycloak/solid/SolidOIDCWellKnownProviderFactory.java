package org.solidproject.keycloak.solid;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.keycloak.wellknown.WellKnownProvider;

public class SolidOIDCWellKnownProviderFactory extends OIDCWellKnownProviderFactory {

    private static final String PROVIDER_ID = "solid-openid-configuration";

    @Override
    public int getPriority() {
        return 0;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getAlias() {
        return OIDCWellKnownProviderFactory.PROVIDER_ID;
    }

    @Override
    public WellKnownProvider create(KeycloakSession session) {
        return new SolidOIDCWellKnownProvider(session);
    }

}
