FROM quay.io/keycloak/keycloak:nightly

COPY target/keycloak-solid-1.0-SNAPSHOT.jar /opt/keycloak/providers/
