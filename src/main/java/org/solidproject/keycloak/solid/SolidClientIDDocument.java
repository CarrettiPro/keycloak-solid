package org.solidproject.keycloak.solid;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties("@context")
public class SolidClientIDDocument {

    @JsonProperty("client_id")
    private String client_id;

    @JsonProperty("client_name")
    private String client_name;

    @JsonProperty("redirect_uris")
    private List<String> redirect_uris;

    @JsonProperty("grant_types")
    private List<String> grant_types;

    public String getClientId() {
        return client_id;
    }

    public void setClientId(String client_id) {
        this.client_id = client_id;
    }

    public String getClientName() {
        return client_name;
    }

    public void setClientName(String client_name) {
        this.client_name = client_name;
    }

    public List<String> getRedirectUris() {
        return redirect_uris;
    }

    public void setRedirectUris(List<String> redirect_uris) {
        this.redirect_uris = redirect_uris;
    }

    public List<String> getGrantTypes() {
        return grant_types;
    }

    public void setGrantTypes(List<String> grant_types) {
        this.grant_types = grant_types;
    }

}
