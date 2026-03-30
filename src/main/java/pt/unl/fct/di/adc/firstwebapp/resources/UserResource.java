package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.cloud.datastore.*;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.google.gson.Gson;
import pt.unl.fct.di.adc.firstwebapp.util.*;

@Path("/")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class UserResource {
    private static final Logger LOG = Logger.getLogger(UserResource.class.getName());
    private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
    private static final String ERR_CODE_INVALID_TOKEN = "9903";
    private static final String ERR_MSG_INVALID_TOKEN = "The operation is called with an invalid token";
    private static final String ERR_CODE_TOKEN_EXPIRED = "9904";
    private static final String ERR_MSG_TOKEN_EXPIRED = "The operation is called with a token that is expired";
    private static final String ERR_CODE_UNAUTHORIZED = "9905";
    private static final String ERR_MSG_UNAUTHORIZED = "The operation is not allowed for the user role";
    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_BOFFICER = "BOFFICER";
    private static final String ROLE_USER = "USER";

    private final Gson g = new Gson();

    public UserResource() { }

    @POST
    @Path("/showusers")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response showUsers(AuthenticatedRequest request) {
        // 1. Validar o Token usando a função auxiliar
        Entity tokenDB = getValidatedToken(request.token);

        if (tokenDB == null) {
            // Se o token não existe ou está corrompido [cite: 104]
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_INVALID_TOKEN, ERR_MSG_INVALID_TOKEN))).build();
        }

        // 2. Verificar se o token já expirou (usando a propriedade da DB) [cite: 104, 114]
        long now = System.currentTimeMillis();
        if (now > tokenDB.getLong("expiresAt")) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_TOKEN_EXPIRED, ERR_MSG_TOKEN_EXPIRED))).build();
        }

        // 3. Verificação de Permissões (RBAC): Apenas ADMIN e BOFFICER
        String role = tokenDB.getString("role");
        if (!role.equals(ROLE_ADMIN) && !role.equals(ROLE_BOFFICER)) {
            LOG.warning("Acesso negado a showUsers para o utilizador: " + request.token.username);
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_UNAUTHORIZED, ERR_MSG_UNAUTHORIZED))).build();
        }

        // 4. Executar a Query para listar todos os utilizadores
        Query<Entity> query = Query.newEntityQueryBuilder()
                .setKind("User")
                .build();
        QueryResults<Entity> results = datastore.run(query);

        // 5. Mapear para a lista simplificada (apenas username e role)
        List<UserShortData> userList = new ArrayList<>();
        results.forEachRemaining(userEntity -> {
            userList.add(new UserShortData(
                    userEntity.getKey().getName(), // O username é a chave
                    userEntity.getString("role")
            ));
        });

        // 6. Enviar resposta no formato exigido: { "status": "success", "data": { "users": [...] } }
        Map<String, List<UserShortData>> dataMap = new HashMap<>();
        dataMap.put("users", userList);

        return Response.ok(g.toJson(new SuccessResponse(dataMap))).build();
    }

    @POST
    @Path("/deleteaccount")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteAccount(AuthenticatedRequest request) {
        Entity tokenDB = getValidatedToken(request.token);

        if (tokenDB == null) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_INVALID_TOKEN, ERR_MSG_INVALID_TOKEN))).build();
        }

        if (!tokenDB.getString("role").equals(ROLE_ADMIN)) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_UNAUTHORIZED, ERR_MSG_UNAUTHORIZED))).build();
        }

        String targetUser = (String) request.input.get("username");
        if (targetUser == null) {
            return Response.ok(g.toJson(new ErrorResponse("9906", "INVALID_INPUT"))).build();
        }

        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(targetUser);
            Entity user = txn.get(userKey);

            if (user == null) {
                txn.rollback();
                return Response.ok(g.toJson(new ErrorResponse("9902", "USER_NOT_FOUND"))).build();
            }

            txn.delete(userKey);

            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Token")
                    .setFilter(StructuredQuery.PropertyFilter.eq("username", targetUser))
                    .build();
            QueryResults<Entity> userTokens = datastore.run(query);
            userTokens.forEachRemaining(t -> txn.delete(t.getKey()));

            txn.commit();
            return Response.ok(g.toJson(new SuccessResponse(Map.of("message", "Account deleted successfully")))).build();

        } catch (Exception e) {
            if (txn.isActive()) txn.rollback();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

    @POST
    @Path("/modaccount")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response modifyAccountAttributes(AuthenticatedRequest request){
        Entity tokenDB = getValidatedToken(request.token);

        if (tokenDB == null) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_INVALID_TOKEN, ERR_MSG_INVALID_TOKEN))).build();
        }

        String targetUsername = (String) request.input.get("username");
        Map<String, String> attributes = (Map<String, String>) request.input.get("attributes");

        if (targetUsername == null || attributes == null) {
            return Response.ok(g.toJson(new ErrorResponse("9906", "INVALID_INPUT"))).build();
        }

        Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
        Entity targetUser = datastore.get(targetUserKey);

        if (targetUser == null) {
            return Response.ok(g.toJson(new ErrorResponse("9902", "USER_NOT_FOUND"))).build();
        }

        String requesterRole = tokenDB.getString("role");
        String requesterUsername = tokenDB.getString("username");
        String targetRole = targetUser.getString("role");

        boolean allowed = false;

        switch (requesterRole) {
            case ROLE_ADMIN -> allowed = true; // Admin pode tudo
            case ROLE_BOFFICER -> {
                // BOFFICER: Própria conta OU conta de um USER
                if (requesterUsername.equals(targetUsername) || targetRole.equals(ROLE_USER)) {
                    allowed = true;
                }
            }
            case ROLE_USER -> {
                // USER: Apenas a própria conta
                if (requesterUsername.equals(targetUsername)) {
                    allowed = true;
                }
            }
        }

        if (!allowed) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_UNAUTHORIZED, ERR_MSG_UNAUTHORIZED))).build();
        }

        Transaction txn = datastore.newTransaction();
        try{
            Entity.newBuilder(txn.get(targetUserKey))
                    .set("phone", attributes.getOrDefault("phone", targetUser.getString("phone")))
                    .set("address", attributes.getOrDefault("address", targetUser.getString("address")))
                    .build();

            Entity updatedUser = Entity.newBuilder(targetUser)
                    .set("phone", attributes.containsKey("phone") ? attributes.get("phone") : targetUser.getString("phone"))
                    .set("address", attributes.containsKey("address") ? attributes.get("address") : targetUser.getString("address"))
                    .build();

            txn.update(updatedUser);
            txn.commit();

            return Response.ok(g.toJson(new SuccessResponse(Map.of("message", "Updated successfully")))).build();
        }catch(Exception e){
            if (txn.isActive()) txn.rollback();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }finally{
            if (txn.isActive()) txn.rollback();
        }
    }

    @POST
    @Path("/showuserrole")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response showUserRole(AuthenticatedRequest request){
        Entity tokenDB = getValidatedToken(request.token);

        if (tokenDB == null) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_INVALID_TOKEN, ERR_MSG_INVALID_TOKEN))).build();
        }

        String targetUsername = (String) request.input.get("username");

        if (targetUsername == null) {
            return Response.ok(g.toJson(new ErrorResponse("9906", "INVALID_INPUT"))).build();
        }

        Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
        Entity targetUser = datastore.get(targetUserKey);

        if (targetUser == null) {
            return Response.ok(g.toJson(new ErrorResponse("9902", "USER_NOT_FOUND"))).build();
        }

        if(tokenDB.getString("role").equals(ROLE_USER)) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_UNAUTHORIZED, ERR_MSG_UNAUTHORIZED))).build();
        }

        Map<String, String> dataMap = new HashMap<>();
        dataMap.put("username", targetUsername);
        dataMap.put("role", targetUser.getString("role"));

        return Response.ok(g.toJson(new SuccessResponse(dataMap))).build();
    }

    @POST
    @Path("/changeuserrole")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeUserRole(AuthenticatedRequest request){
        Entity tokenDB = getValidatedToken(request.token);

        if (tokenDB == null) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_INVALID_TOKEN, ERR_MSG_INVALID_TOKEN))).build();
        }

        String targetUsername = (String) request.input.get("username");
        String newRole = (String) request.input.get("newRole");

        if (targetUsername == null || newRole == null || !isValidRole(newRole)) {
            return Response.ok(g.toJson(new ErrorResponse("9906", "INVALID_INPUT"))).build();
        }

        if (!tokenDB.getString("role").equals(ROLE_ADMIN)) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_UNAUTHORIZED, ERR_MSG_UNAUTHORIZED))).build();
        }

        Transaction txn = datastore.newTransaction();
        try {
            Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = txn.get(targetUserKey);

            if (targetUser == null) {
                txn.rollback();
                return Response.ok(g.toJson(new ErrorResponse("9902", "USER_NOT_FOUND"))).build();
            }

            Entity updatedUser = Entity.newBuilder(targetUser)
                    .set("role", newRole)
                    .build();

            txn.update(updatedUser);
            txn.commit();
            LOG.info("ADMIN " + request.token.username + " alterou role de " + targetUsername + " para " + newRole);

            return Response.ok(g.toJson(new SuccessResponse(Map.of("message", "Role updated successfully")))).build();

        } catch (Exception e) {
            if (txn.isActive()) txn.rollback();
            LOG.severe("Erro ao alterar role: " + e.getMessage());
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            if (txn.isActive()) txn.rollback();
        }

    }

    @POST
    @Path("/changeuserpwd") // Endpoint oficial (Pág. 4 e 12)
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changeUserPassword(AuthenticatedRequest request) {
        Entity tokenDB = getValidatedToken(request.token);
        if (tokenDB == null) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_INVALID_TOKEN, ERR_MSG_INVALID_TOKEN))).build();
        }

        String targetUsername = (String) request.input.get("username");
        String oldPassword = (String) request.input.get("oldPassword");
        String newPassword = (String) request.input.get("newPassword");

        if (targetUsername == null || oldPassword == null || newPassword == null) {
            return Response.ok(g.toJson(new ErrorResponse("9906", "INVALID_INPUT"))).build();
        }

        String requesterUsername = tokenDB.getString("username");
        String requesterRole = tokenDB.getString("role");

        if (!requesterUsername.equals(targetUsername) && !requesterRole.equals(ROLE_ADMIN)) {
            return Response.ok(g.toJson(new ErrorResponse(ERR_CODE_UNAUTHORIZED, ERR_MSG_UNAUTHORIZED))).build();
        }

        Transaction txn = datastore.newTransaction();
        try {
            Key targetUserKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity targetUser = txn.get(targetUserKey);

            if (targetUser == null) {
                txn.rollback();
                return Response.ok(g.toJson(new ErrorResponse("9902", "USER_NOT_FOUND"))).build();
            }

            String currentPasswordHash = targetUser.getString("user_pwd");
            if (!currentPasswordHash.equals(DigestUtils.sha512Hex(oldPassword))) {
                txn.rollback();
                return Response.ok(g.toJson(new ErrorResponse("9900", "INVALID_CREDENTIALS"))).build();
            }

            // 5. Atualizar para a nova password (com hash)
            Entity updatedUser = Entity.newBuilder(targetUser)
                    .set("user_pwd", DigestUtils.sha512Hex(newPassword))
                    .build();

            txn.update(updatedUser);
            txn.commit();

            LOG.info("Password alterada com sucesso para: " + targetUsername);
            return Response.ok(g.toJson(new SuccessResponse(Map.of("message", "Password changed successfully")))).build();

        } catch (Exception e) {
            if (txn.isActive()) txn.rollback();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        } finally {
            if (txn.isActive()) txn.rollback();
        }
    }

    private Entity getValidatedToken(AuthToken tokenFromRequest) {
        if (tokenFromRequest == null || tokenFromRequest.tokenId == null) {
            return null;
        }

        Key tokenKey = datastore.newKeyFactory().setKind("Token").newKey(tokenFromRequest.tokenId);
        Entity tokenEntity = datastore.get(tokenKey);

        // Valida existência e se o username no JSON condiz com o dono do token na DB
        if (tokenEntity == null || !tokenEntity.getString("username").equals(tokenFromRequest.username)) {
            return null;
        }

        // Valida expiração (usa "expiresAt" com e minúsculo para consistência) [cite: 85-88]
        long now = System.currentTimeMillis();
        if (now > tokenEntity.getLong("expiresAt")) {
            return null;
        }

        return tokenEntity;
    }

    private boolean isValidRole(String r) {
        return r.equals("USER") || r.equals("BOFFICER") || r.equals("ADMIN");
    }

}


