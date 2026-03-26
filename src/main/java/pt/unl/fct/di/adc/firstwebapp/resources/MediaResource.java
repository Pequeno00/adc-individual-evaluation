package pt.unl.fct.di.adc.firstwebapp.resources;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.concurrent.TimeUnit;

import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.HttpMethod;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import jakarta.ws.rs.core.Response.Status;

@Path("/media")
public class MediaResource {

	@GET
	@Path("/download/{bucket}/{object}")
	public Response downloadFile(@PathParam("bucket") String bucket, @PathParam("object") String object) {

		Storage storage = StorageOptions.getDefaultInstance().getService();
		Blob blob = storage.get(BlobId.of(bucket, object));

		StreamingOutput stream = new StreamingOutput() {

			@Override
			public void write(OutputStream output) throws IOException {

				// Download object to the output stream. See Google's documentation.
				blob.downloadTo(output);
				output.flush();
			}
		};

		return Response.ok(stream)
				.header("Content-Type", blob.getContentType())
				.build();
	}

	@GET
	@Path("/download2/{bucket}/{object}")
	@Produces(MediaType.APPLICATION_OCTET_STREAM)
	public Response downloadFile2(@PathParam("bucket") String bucket, @PathParam("object") String object) {

		Storage storage = StorageOptions.getDefaultInstance().getService();
		Blob blob = storage.get(BlobId.of(bucket, object));

		return Response.ok(blob.getContent())
				.header("Content-Type", blob.getContentType())
				.build();
	}

        @POST
    @Path("/upload/{bucket}/{object}")
    public Response uploadFile(@PathParam("bucket") String bucket, @PathParam("object") String object,
            @HeaderParam("Content-Type") String contentType) {

        Storage storage = StorageOptions.getDefaultInstance().getService();
        BlobId blobId = BlobId.of(bucket, object);
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType(contentType).build();

        // Generate a Signed URL that allows the client to PUT the file directly to GCS.
        // The link is valid for 15 minutes.
        URL url = storage.signUrl(blobInfo, 15, TimeUnit.MINUTES, 
                Storage.SignUrlOption.httpMethod(HttpMethod.PUT),
                Storage.SignUrlOption.withContentType(),
                Storage.SignUrlOption.withV4Signature());

        return Response.ok(url.toString()).build();
    }

	@POST
	@Path("/upload2/{bucket}/{object}")
	public Response uploadFile2(@PathParam("bucket") String bucket, @PathParam("object") String object,
			@HeaderParam("Content-Type") String contentType,
			@Context HttpServletRequest request) {

		// Upload to Google Cloud Storage (see Google's documentation)
		Storage storage = StorageOptions.getDefaultInstance().getService();
		BlobId blobId = BlobId.of(bucket, object);
		BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType(contentType).build();
		// The following is deprecated since it is better to upload directly to GCS from
		// the client
		try {
			storage.createFrom(blobInfo, request.getInputStream());
			return Response.ok().build();
		} catch (IOException e) {
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		}
	}
}