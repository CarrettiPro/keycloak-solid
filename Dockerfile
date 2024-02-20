FROM quay.io/keycloak/keycloak:23.0.6

COPY target/keycloak-solid-1.0-SNAPSHOT.jar /opt/keycloak/providers/
