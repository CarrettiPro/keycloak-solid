FROM keycloak:999-SNAPSHOT-solid

COPY target/keycloak-solid-1.0-SNAPSHOT.jar /opt/keycloak/providers/
