package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import com.google.gson.Gson;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.Transaction;
import com.google.cloud.datastore.DatastoreOptions;

import pt.unl.fct.di.adc.firstwebapp.util.*;

@Path("/register")
public class RegisterResource {

	private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();


	public RegisterResource() {}	// Default constructor, nothing to do

    @POST
    @Path("/")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createAccount(RegisterRequest wrapper) {
        RegisterData data = wrapper.input;

        // 1. Validar inputs básicos
        if(!data.validRegistration() || data.role == null) {
            return Response.ok(g.toJson(new ErrorResponse("9906", "INVALID_INPUT"))).build();
        }

        Transaction txn = datastore.newTransaction();
        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
            Entity user = txn.get(userKey);

            if(user != null) {
                txn.rollback();
                return Response.ok(g.toJson(new ErrorResponse("9901", "USER_ALREADY_EXISTS"))).build();
            }

            user = Entity.newBuilder(userKey)
                    .set("user_pwd", DigestUtils.sha512Hex(data.password))
                    .set("user_email", data.email)
                    .set("role", data.role)
                    .set("phone", data.phone)
                    .set("address", data.address)
                    .set("user_creation_time", Timestamp.now())
                    .build();

            txn.put(user);
            txn.commit();

            Map<String, String> result = new HashMap<>();
            result.put("username", data.username);
            result.put("role", data.role);

            return Response.ok(g.toJson(new SuccessResponse(result))).build();

        } catch (Exception e) {
            if(txn.isActive()) txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
    }
}