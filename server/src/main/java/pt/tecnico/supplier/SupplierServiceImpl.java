package pt.tecnico.supplier;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import com.google.type.Money;
import com.google.protobuf.ByteString;

import pt.tecnico.supplier.grpc.SignedResponse;
import pt.tecnico.supplier.grpc.Signature;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import io.grpc.stub.StreamObserver;
import pt.tecnico.supplier.domain.Supplier;
import pt.tecnico.supplier.grpc.Product;
import pt.tecnico.supplier.grpc.ProductsRequest;
import pt.tecnico.supplier.grpc.ProductsResponse;
import pt.tecnico.supplier.grpc.SupplierGrpc;

public class SupplierServiceImpl extends SupplierGrpc.SupplierImplBase {

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

	/** Domain object. */
	final private Supplier supplier = Supplier.getInstance();
  private PrivateKey privateKey;

	/** Constructor */
	public SupplierServiceImpl() {
		debug("Loading demo data...");
		supplier.demoData();
    try {
        this.privateKey = loadPrivateKey("private.der");
        System.out.println("Chave privada do servidor carregada com sucesso.");
    } catch (Exception e) {
        System.err.println("Erro ao carregar a chave privada: " + e.getMessage());
        e.printStackTrace();
    }
	}

  public byte[] readResource(String path) throws Exception {
    try (InputStream is = getClass().getClassLoader().getResourceAsStream(path)) {
      if (is == null) {
        throw new IllegalArgumentException("File not found: " + path);
      }
      return is.readAllBytes();
    }
  }

  public PrivateKey loadPrivateKey(String resourcePath) throws Exception {
    byte[] keyBytes = readResource(resourcePath);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(spec);
  }

	/** Helper method to convert domain product to message product. */
	private Product buildProductFromProduct(pt.tecnico.supplier.domain.Product p) {
		Product.Builder productBuilder = Product.newBuilder();
		productBuilder.setIdentifier(p.getId());
		productBuilder.setDescription(p.getDescription());
		productBuilder.setQuantity(p.getQuantity());

		Money.Builder moneyBuilder = Money.newBuilder();
		moneyBuilder.setCurrencyCode("EUR").setUnits(p.getPrice());
		productBuilder.setPrice(moneyBuilder.build());

		return productBuilder.build();
	}

	@Override
	public void listProducts(ProductsRequest request, StreamObserver<SignedResponse> responseObserver) {
		debug("listProducts called");
    
    try  {
      java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");


      debug("Received request:");
      debug(request.toString());
      debug("in binary hexadecimals:");
      byte[] requestBinary = request.toByteArray();
      debug(String.format("%d bytes%n", requestBinary.length));

      // build response
      ProductsResponse.Builder responseBuilder = ProductsResponse.newBuilder();
      responseBuilder.setSupplierIdentifier(supplier.getId());
      for (String pid : supplier.getProductsIDs()) {
        pt.tecnico.supplier.domain.Product p = supplier.getProduct(pid);
        Product product = buildProductFromProduct(p);
        responseBuilder.addProduct(product);
      }
      ProductsResponse response = responseBuilder.build();
      sig.initSign(this.privateKey);

      debug("Response to send:");
      debug(response.toString());
      debug("in binary hexadecimals:");
      byte[] responseBinary = response.toByteArray();

      sig.update(response.toByteArray());
      byte[] signatureBytes = sig.sign();

      debug(printHexBinary(responseBinary));
      debug(String.format("%d bytes%n", responseBinary.length));

      Signature signature = Signature.newBuilder()
              .setSignerIdentifier(supplier.getId())
              .setSignatureValue(ByteString.copyFrom(signatureBytes))
              .build();
      SignedResponse signedResponse = SignedResponse.newBuilder()
              .setResponse(response)
              .setSignature(signature)
              .build();

      responseObserver.onNext(signedResponse);
      responseObserver.onCompleted();

    } catch (java.security.NoSuchAlgorithmException e) {
			debug("NoSuchAlgorithmException in listProducts: " + e.getMessage());
			e.printStackTrace();
			responseObserver.onError(e);

		} catch (java.security.InvalidKeyException e) {
			debug("InvalidKeyException in listProducts: " + e.getMessage());
			e.printStackTrace();
			responseObserver.onError(e);

		} catch (java.security.SignatureException e) {
			debug("SignatureException in listProducts: " + e.getMessage());
			e.printStackTrace();
			responseObserver.onError(e);

		} catch (Exception e) {
			debug("Error in listProducts: " + e.getMessage());
			e.printStackTrace();
			responseObserver.onError(e);
		}
	}

}
