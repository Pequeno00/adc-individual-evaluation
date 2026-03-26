package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.logging.Logger;

import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
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

import pt.unl.fct.di.adc.firstwebapp.util.LoginData;
import pt.unl.fct.di.adc.firstwebapp.util.RegisterData;

@Path("/register")
public class RegisterResource {

	private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();


	public RegisterResource() {}	// Default constructor, nothing to do
	
	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	
	public Response registerUserV1(LoginData data) {
		LOG.fine("Attempt to register user: " + data.username);
	
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Entity user = Entity.newBuilder(userKey)
						.set("user_pwd", DigestUtils.sha512Hex(data.password))
						.set("user_creation_time", Timestamp.now())
						.build();
		datastore.put(user);
		LOG.info("User registered " + data.username);
		return Response.ok().entity(g.toJson(true)).build();
    }

    @POST
	@Path("/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response registerUserV2(RegisterData data) {
		LOG.fine("Attempt to register user: " + data.username);

		if(!data.validRegistration())
			return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameter.").build();
					
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Entity user = datastore.get(userKey);
		
		if(user != null)
			return Response.status(Status.BAD_REQUEST).entity("User already exists.").build();
		
		user = Entity.newBuilder(userKey)
				.set("user_name", data.name)
				.set("user_pwd", DigestUtils.sha512Hex(data.password))
				.set("user_email", data.email)
				.set("user_creation_time", Timestamp.now())
				.build();

		// Concurrency problem...
		// When we reach here, another client might have put() an entity with the same key...
		
		datastore.put(user);
		LOG.info("User registered " + data.username);
		
		
		return Response.ok().build();
	}

    @POST
    @Path("/v3")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response registerUserV3(RegisterData data) {
        LOG.fine("Attempt to register user: " + data.username);

        if(!data.validRegistration())
            return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameter.").build();

        try {
            Transaction txn = datastore.newTransaction();
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
            Entity user = txn.get(userKey);

            if(user != null) {
                txn.rollback();
                return Response.status(Status.CONFLICT).entity("User already exists.").build();
            }            
            else {
                user = Entity.newBuilder(userKey)
                        .set("user_name", data.name)
                        .set("user_pwd", DigestUtils.sha512Hex(data.password))
                        .set("user_email", data.email)
                        .set("user_creation_time", Timestamp.now())
                        .build();
                txn.put(user);
                txn.commit();
                LOG.info("User registered " + data.username);
                return Response.ok().build();
            }
        } catch (Exception e) {
            LOG.severe("Error registering user: " + e.getMessage());
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Error registering user.").build();
        }
        finally {
            // No need to rollback here, as we only have one transaction and it will be automatically rolled back if not committed.
        }
    }
}