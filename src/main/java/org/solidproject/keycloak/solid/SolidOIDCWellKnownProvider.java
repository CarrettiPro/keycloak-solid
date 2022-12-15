package org.solidproject.keycloak.solid;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCWellKnownProvider;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

public class SolidOIDCWellKnownProvider extends OIDCWellKnownProvider {

    private static final List<String> SOLID_CLAIMS_SUPPORTED = Arrays.asList("webid", "client_id");

    public SolidOIDCWellKnownProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    public Object getConfig() {
        OIDCConfigurationRepresentation config = (OIDCConfigurationRepresentation) super.getConfig();
        List<String> claimsSupported = new ArrayList<>(DEFAULT_CLAIMS_SUPPORTED);
        claimsSupported.addAll(SOLID_CLAIMS_SUPPORTED);
        config.setClaimsSupported(claimsSupported);
        return config;
    }

}
