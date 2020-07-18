package com.gwidgets.resources;

import java.util.List;
import java.util.Objects;
import java.util.ArrayList;
import java.util.Set;
import java.util.Iterator;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.ClientModel;
import com.google.gson.Gson;

public class ApiKeyResource {

    private KeycloakSession session;

    private final String realmName;

    public ApiKeyResource(KeycloakSession session) {
        this.session = session;
        String envRealmName = System.getenv("REALM_NAME");
        this.realmName = Objects.isNull(envRealmName) || Objects.equals(System.getenv(envRealmName), "")? "example": envRealmName;
    }

    @GET
    @Produces("application/json")
    public Response checkApiKey(@QueryParam("apiKey") String apiKey,
                @QueryParam("realm") String realmname,
                @QueryParam("client") String clientname) {
        List<UserModel> result = session.userStorageManager().searchForUserByUserAttribute("api-key", apiKey, session.realms().getRealm(realmname));

        if (result.isEmpty()) {
                return Response.status(401).build();
        }

        ClientModel client = session.realms().getRealm(realmname).getClientByClientId(clientname);
        ArrayList<String> l = new ArrayList<String>();
        if (client != null) {
            // hopefully no clashes ...
            Set<RoleModel> roles = result.get(0).getClientRoleMappings(client);
            Iterator<RoleModel> setit = roles.iterator();
            while (setit.hasNext()) {
                l.add(setit.next().getName());
            }
        }

        String json = new Gson().toJson(l);
        return Response.ok(json).build();
    }
}
