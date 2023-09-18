package org.solidproject.keycloak.solid;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.keycloak.representations.oidc.OIDCClientRepresentation;

@JsonIgnoreProperties("@context")
public class SolidOIDCClientRepresentation extends OIDCClientRepresentation {

}
