package cliente;

import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Random;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Provider;
import java.security.Security;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Cliente 
{
	/**
	 * Socket de comunicación
	 */
	private static Socket socket;
	/**
	 * Identificador del cliente
	 */
	private static int id_cliente;
	/**
	 * Certificado digital del cliente
	 */
	private static X509Certificate certificadoCliente;
	/**
	 * Certificado digital del servidor
	 */
	private static X509Certificate certificadoServidor;
	/**
	 * Tupla de llave (pública-privada del cliente
	 */
	private static KeyPair keyPairCliente;
	/**
	 * Puerto de comunicación entre cliente-servidor
	 */
	private static int puerto;
	/**
	 * Host para la conexión
	 */
	private final static String HOST = "localhost"; 
	/**
	 * Métdo main del cliente
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception
	{
		// -----------------------------------------------------------------
	    // Etapa1: Seleccionar algoritmos e iniciar sesión
	    // -----------------------------------------------------------------
		
		System.out.println("Establezca el puerto conexión: ");
		InputStreamReader input = new InputStreamReader(System.in);
		BufferedReader br = new BufferedReader(input);
		puerto = Integer.parseInt(br.readLine());

		//Creación del identificador del cliente
		Random numAleatorio = new Random();
		id_cliente = numAleatorio.nextInt(9999-1000+1) + 1000;

		//Asegurando conexion con el cliente
		System.out.println("Empezando cliente "+ id_cliente +" en puerto: " + puerto);        
		Security.addProvider((Provider)new BouncyCastleProvider());

		//Preparando el socket para comunicación
		socket = new Socket(HOST, puerto);
		PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
		br = new BufferedReader(new InputStreamReader(socket.getInputStream()));

		System.out.println("Cliente inicializado en el puerto: "+puerto);
		writer.println(Mns_Alg.mns_inicComunicacion());

		//Respuesta del servidor 
		String respuestaServidor = br.readLine();

		if(Mns_Alg.verificarError(respuestaServidor))
		{
			System.out.println("Hubo un error en la comunicación");
			socket.close();
		}
		else
		{
			System.out.println("Comenzó el protocolo de comunicación");
		}

		writer.println(Mns_Alg.mns_algoritmos());

		respuestaServidor = br.readLine();
		if(Mns_Alg.verificarError(respuestaServidor))
		{
			System.out.println("Hubo un error en la comunicación");
			socket.close();
		}
		else
		{
			System.out.println("Se enviaron los algoritmos seleccionados");
		}
		
		// -----------------------------------------------------------------
	    // Etapa2: Autenticación de	cliente	y servidor
	    // -----------------------------------------------------------------
		
		//Creación del par de llave pública y privada del del cliente
		try 
		{keyPairCliente = Mns_Alg.llaveCliente();}
		catch (Exception e) 
		{System.out.println("Error en la creación de la llave: " + e.getMessage());}

		//Creación de certifado del cliente
		try 
		{certificadoCliente = generarCertificadoCliente(keyPairCliente);}
		catch (Exception e) 
		{System.out.println("Error en la creación del certificado: " + e.getMessage());}

		//Envío del certificado del cliente al servidor
		byte[] certificadoByte = certificadoCliente.getEncoded();
		String certificadoString = DatatypeConverter.printBase64Binary(certificadoByte);
		writer.println(certificadoString);

		respuestaServidor = br.readLine();
		if(Mns_Alg.verificarError(respuestaServidor))
		{
			System.out.println("Hubo un error en la comunicación");
			socket.close();
		}
		else
		{
			System.out.println("Se envío el certificado digital del cliente al servidor");
		}

		//Obtención del certificado del servidor
		String strCertificadoServidor = br.readLine(); 
		System.out.println("Se recibió el certificado digital del servidor");
		
		try 
		{
			writer.println(Mns_Alg.mns_OK());
			certificadoServidor = convertirCertificado(strCertificadoServidor);
		} 
		catch (Exception e) 
		{
			writer.println(Mns_Alg.mns_Error());
			socket.close();
		}
		
		//Recepción de C(K_C+,K_SC)
		respuestaServidor = br.readLine();
		SecretKey llaveBlowfish = Mns_Alg.llavePrivadaServidor(keyPairCliente, respuestaServidor);
		
		//Recepción de C(K_SC,<reto>)
		respuestaServidor = br.readLine();
		byte[] reto = Mns_Alg.descifrar(llaveBlowfish, Mns_Alg.BLOWFISH, DatatypeConverter.parseBase64Binary(respuestaServidor));
		System.out.println("Se recibió el reto: "+ DatatypeConverter.printBase64Binary(reto));
		
		
		//Envío de C(K_S+,<reto>)
		byte[] retoCifrado = Mns_Alg.cifrar(certificadoServidor.getPublicKey(), Mns_Alg.RSA, DatatypeConverter.printBase64Binary(reto));
		writer.println(DatatypeConverter.printBase64Binary(retoCifrado));
		
		respuestaServidor = br.readLine();
		if(Mns_Alg.verificarError(respuestaServidor))
		{
			System.out.println("Hubo un error en la comunicación");
			socket.close();
		}
		else
		{
			System.out.println("Se envió el reto del cliente al servidor");
		}
		
		// -----------------------------------------------------------------
	    // Etapa3: Reporte y manejo	de la actualización
	    // -----------------------------------------------------------------
		
		//Envío de C(K_SC,<idUsuario>)
		byte[] idClienteCifrado = Mns_Alg.cifrar(llaveBlowfish, Mns_Alg.BLOWFISH, Integer.toString(id_cliente));
		writer.println(DatatypeConverter.printBase64Binary(idClienteCifrado));
		System.out.println("Se envío el identificador del cliente al servidor");
		
		//Recepción de C(K_SC,<hhmm>)
		respuestaServidor = br.readLine();
		try 
		{
			String horario = Mns_Alg.descifrarHHMM(llaveBlowfish, Mns_Alg.BLOWFISH, DatatypeConverter.parseBase64Binary(respuestaServidor));
			System.out.println("La hora enviada por el servidor es: "+ horario);
			writer.println(Mns_Alg.mns_OK());
			System.out.println("Se terminó la ejecución correctamente.");
			socket.close();
		} 
		catch (Exception e) 
		{
			writer.println(Mns_Alg.mns_Error());
			socket.close();
		}
		
	}
	/**
	 * Transforma una cadena de caracteres en un certificado X509
	 * @param certServidor Cadena de caracteres que conforman el certificado
	 * @return Certificado digital de la forma X509
	 * @throws CertificateException En caso de que no se pueda formar el certificado correctamente
	 */
	private static X509Certificate convertirCertificado(String certServidor) throws CertificateException
	{
		byte[] certiServidorByte = new byte[520];
		certiServidorByte = DatatypeConverter.parseBase64Binary(certServidor);
		CertificateFactory creador = CertificateFactory.getInstance("X.509");
		InputStream in = new ByteArrayInputStream(certiServidorByte);
		return (X509Certificate)creador.generateCertificate(in);
	}
	/**
	 * Genera el certificado digital del cliente con base a una tupla de llave(pública-privada)
	 * @param kepair Tupla de llave (pública-privada) del cliente
	 * @return certificado digital del cliente
	 * @throws Exception En caso de que no se pueda crear correctamente el certificado
	 */
	private static X509Certificate generarCertificadoCliente(KeyPair kepair) throws Exception
	{
		Calendar endCalendar = Calendar.getInstance();
		endCalendar.add(Calendar.YEAR, 10);
		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(new X500Name("CN=localhost"), 
				BigInteger.valueOf(1), Calendar.getInstance().getTime(), 
				endCalendar.getTime(), new X500Name("CN=localhost"), 
				SubjectPublicKeyInfo.getInstance(keyPairCliente.getPublic().getEncoded()));
		ContentSigner contentsigner = new JcaContentSignerBuilder("SHA1withRSA").build(keyPairCliente.getPrivate());
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentsigner);
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(x509CertificateHolder);
	}


}
