package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.Map;
import java.util.HashMap;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.servlet.http.HttpServletRequest;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import pt.unl.fct.di.adc.firstwebapp.util.*;

@Path("/")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

    private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
    private static final String ERR_CODE_INVALID_TOKEN = "9903";
    private static final String ERR_MSG_INVALID_TOKEN = "The operation is called with an invalid token";
    private static final String ERR_CODE_TOKEN_EXPIRED = "9904";
    private static final String ERR_MSG_TOKEN_EXPIRED = "The operation is called with a token that is expired";
    private static final String ERR_CODE_UNAUTHORIZED = "9905";
    private static final String ERR_MSG_UNAUTHORIZED = "The operation is not allowed for the user role";
    private static final String INVALID_INPUT = "The call is using input data not following the correct specification";
    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_BOFFICER = "BOFFICER";
    private static final String ROLE_USER = "USER";
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private final Gson g = new Gson();

    // Códigos e Mensagens de Erro conforme o Enunciado [cite: 104]
    private static final String ERR_CODE_INVALID_CREDENTIALS = "9900";
    private static final String ERR_MSG_INVALID_CREDENTIALS = "The username-password pair is not valid";

    // Constantes de Sucesso e Base de Dados
    private static final String STATUS_SUCCESS = "success";
    private static final String KIND_USER = "User";
    private static final String KIND_TOKEN = "Token";
    private static final String KIND_USER_LOG = "UserLog";

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response doLogin(LoginRequest wrapper, @Context HttpServletRequest request, @Context HttpHeaders headers) {
        LoginData data = wrapper.input;
        LOG.info("Tentativa de login para o utilizador: " + data.username);

        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().setKind(KIND_USER).newKey(data.username);
            Entity user = txn.get(userKey);

            if (user == null || !user.getString("user_pwd").equals(DigestUtils.sha512Hex(data.password))) {
                LOG.warning("Falha na autenticação para: " + data.username);
                return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_INVALID_CREDENTIALS, ERR_MSG_INVALID_CREDENTIALS))).build();
            }

            String role = user.contains("role") ? user.getString("role") : "USER";
            AuthToken token = new AuthToken(data.username, role);

            Key tokenKey = datastore.newKeyFactory().setKind(KIND_TOKEN).newKey(token.tokenId);
            Entity tokenEntity = Entity.newBuilder(tokenKey)
                    .set("username", token.username)
                    .set("role", token.role)
                    .set("issuedAt", token.issuedAt)
                    .set("expiresAt", token.expiresAt)
                    .build();

            Key logKey = datastore.allocateId(datastore.newKeyFactory()
                    .addAncestor(PathElement.of(KIND_USER, data.username)).setKind(KIND_USER_LOG).newKey());

            Entity loginLog = Entity.newBuilder(logKey)
                    .set("user_login_time", Timestamp.now())
                    .set("user_login_ip", request.getRemoteAddr())
                    .build();

            // Guardar tudo atomicamente
            txn.put(tokenEntity, loginLog);
            txn.commit();

            Map<String, Object> dataMap = new HashMap<>();
            dataMap.put("token", token);

            LOG.info("Login bem-sucedido: " + data.username);
            return Response.ok(g.toJson(new SuccessResponse(dataMap))).build();

        } catch (Exception e) {
            if (txn.isActive()) txn.rollback();
            LOG.severe("Erro interno no processo de login: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            if (txn.isActive()) txn.rollback();
        }
    }

    @POST
    @Path("/logout")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response doLogout(AuthenticatedRequest request) {
        Entity tokenDB = getValidatedToken(request.token);

        if (tokenDB == null) {
            return Response.ok(g.toJson(new ErrorResponse("9903", ERR_MSG_INVALID_TOKEN))).build();
        }


        String requesterUsername = tokenDB.getString("username");
        String requesterRole = tokenDB.getString("role");
        String targetUsername = (String) request.input.get("username");

        if (targetUsername == null) {
            return Response.ok(g.toJson(new ErrorResponse("9906", INVALID_INPUT))).build();
        }

        if (!requesterRole.equals("ADMIN") && !requesterUsername.equals(targetUsername)) {
            return Response.ok(g.toJson(new ErrorResponse("9905", ERR_MSG_UNAUTHORIZED))).build();
        }

        Transaction txn = datastore.newTransaction();
        try {
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Token")
                    .setFilter(com.google.cloud.datastore.StructuredQuery.PropertyFilter.eq("username", targetUsername))
                    .build();
            QueryResults<Entity> results = datastore.run(query);
            results.forEachRemaining(t -> txn.delete(t.getKey()));

            txn.commit();
            LOG.info("Logout realizado com sucesso para: " + targetUsername);
            return Response.ok(g.toJson(new SuccessResponse(Map.of("message", "Logout successful")))).build();

        } catch (Exception e) {
            if (txn.isActive()) txn.rollback();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            if (txn.isActive()) txn.rollback();
        }
    }

    @POST
    @Path("/showauthsessions")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response showAuthenticatedSessions(AuthenticatedRequest request){
        Entity token = getValidatedToken(request.token);

        if (token == null) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_INVALID_TOKEN, ERR_MSG_INVALID_TOKEN))).build();
        }

        if (!token.getString("role").equals(ROLE_ADMIN)) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_UNAUTHORIZED, ERR_MSG_UNAUTHORIZED))).build();
        }

        Query<Entity> query = Query.newEntityQueryBuilder()
                .setKind("Token")
                .build();
        QueryResults<Entity> results = datastore.run(query);

        List<Map<String, Object>> sessionsList = new ArrayList<>();
        results.forEachRemaining(tokenEntity -> {
            Map<String, Object> sessionData = new HashMap<>();
            sessionData.put("tokenId", tokenEntity.getKey().getName());
            sessionData.put("username", tokenEntity.getString("username"));
            sessionData.put("role", tokenEntity.getString("role"));
            sessionData.put("expiresAt", tokenEntity.getLong("expiresAt"));
            sessionsList.add(sessionData);
        });

        Map<String, List<Map<String, Object>>> dataMap = new HashMap<>();
        dataMap.put("sessions", sessionsList);

        return Response.ok(g.toJson(new SuccessResponse(dataMap))).build();
    }

    private Entity getValidatedToken(AuthToken tokenFromRequest) {
        if (tokenFromRequest == null || tokenFromRequest.tokenId == null) {
            return null;
        }

        Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(tokenFromRequest.tokenId);
        Entity tokenEntity = datastore.get(tokenKey);

        if (tokenEntity == null || !tokenEntity.getString("username").equals(tokenFromRequest.username)) {
            return null;
        }

        long now = System.currentTimeMillis();
        if (now > tokenEntity.getLong("expiresAt")) {
            return null;
        }

        return tokenEntity;
    }
}
