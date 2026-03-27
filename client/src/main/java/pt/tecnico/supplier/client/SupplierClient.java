package pt.tecnico.supplier.client;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import pt.tecnico.supplier.grpc.SignedResponse;
import pt.tecnico.supplier.grpc.Signature;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import pt.tecnico.supplier.grpc.ProductsRequest;
import pt.tecnico.supplier.grpc.ProductsResponse;
import pt.tecnico.supplier.grpc.SupplierGrpc;

public class SupplierClient {

	/**
	 * Set flag to true to print debug messages. The flag can be set using the
	 * -Ddebug command line option.
	 */
	private static final boolean DEBUG_FLAG = (System.getProperty("debug") != null);

	/** Helper method to print debug messages. */
	private static void debug(String debugMessage) {
		if (DEBUG_FLAG)
			System.err.println(debugMessage);
	}

  private static PublicKey loadPublicKey(String resourcePath) throws Exception {
      byte[] keyBytes = readResource(resourcePath);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return kf.generatePublic(spec); 
  }

  private static byte[] readResource(String path) throws Exception {
    try (InputStream is = SupplierClient.class.getClassLoader().getResourceAsStream(path)) {
      if (is == null) {
        throw new IllegalArgumentException("File not found: " + path);
      }
      return is.readAllBytes();
    }
  }

	public static void main(String[] args) throws Exception {
		System.out.println(SupplierClient.class.getSimpleName() + " starting ...");

		// Receive and print arguments.
		System.out.printf("Received %d arguments%n", args.length);
		for (int i = 0; i < args.length; i++) {
			System.out.printf("arg[%d] = %s%n", i, args[i]);
		}

		// Check arguments.
		if (args.length < 2) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s host port%n", SupplierClient.class.getName());
			return;
		}
    try {
      PublicKey publicKey = null;
      publicKey = loadPublicKey("public.der");
      System.out.println("Servers public key loaded successfully.");


      final String host = args[0];
      final int port = Integer.parseInt(args[1]);
      final String target = host + ":" + port;

      java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
      sig.initVerify(publicKey);

      // Channel is the abstraction to connect to a service end-point.
      final ManagedChannel channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();

      // Create a blocking stub for making synchronous remote calls.
      SupplierGrpc.SupplierBlockingStub stub = SupplierGrpc.newBlockingStub(channel);

      // Prepare request.
      ProductsRequest request = ProductsRequest.newBuilder().build();
      System.out.println("Request to send:");
      System.out.println(request.toString());
      debug("in binary hexadecimals:");
      byte[] requestBinary = request.toByteArray();
      debug(printHexBinary(requestBinary));
      debug(String.format("%d bytes%n", requestBinary.length));

      // Make the call using the stub.
      System.out.println("Remote call...");
      SignedResponse signedResponse = stub.listProducts(request);

      ProductsResponse response = signedResponse.getResponse();
      Signature receivedSignature = signedResponse.getSignature();
      byte[] responseBinary = response.toByteArray();
      // Print response.
      System.out.println("Received response:");
      System.out.println(response.toString());
      debug("in binary hexadecimals:");
      debug(printHexBinary(responseBinary));
      debug(String.format("%d bytes%n", responseBinary.length));

      sig.update(response.toByteArray());

      boolean isValid = sig.verify(receivedSignature.getSignatureValue().toByteArray());

      String responseState = "invalid";
      if (isValid) responseState = "valid";
      System.out.println("Response is " + responseState);

      // A Channel should be shutdown before stopping the process.
      channel.shutdownNow();
    
    } catch (java.security.NoSuchAlgorithmException e) {
			debug("NoSuchAlgorithmException in listProducts: " + e.getMessage());
			e.printStackTrace();

		} catch (java.security.InvalidKeyException e) {
			debug("InvalidKeyException in listProducts: " + e.getMessage());
			e.printStackTrace();

		} catch (java.security.SignatureException e) {
			debug("SignatureException in listProducts: " + e.getMessage());
			e.printStackTrace();

		} catch (Exception e) {
			debug("Error in listProducts: " + e.getMessage());
			e.printStackTrace();
		}
	}

}
