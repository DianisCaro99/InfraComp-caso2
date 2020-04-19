package cliente;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Mns_Alg
{
	// -----------------------------------------------------------------
    // Mensajes del protocolo de comunicación
    // -----------------------------------------------------------------
	public static final String HOLA = "HOLA";
	public static final String OK = "OK";
	public static final String ERROR = "ERROR";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String SEPARADOR_PRINCIPAL = ":";
	// -----------------------------------------------------------------
    // Algoritmos para el manejo de confidencialidad e integridad
    // -----------------------------------------------------------------
	public static final String BLOWFISH = "Blowfish";
	public static final String RSA = "RSA";
	public static final String HMACSHA512 = "HMACSHA512";
	/**
	 * Mensaje de comunicación inicial
	 * @return mensaje inicial
	 */
	public static String mns_inicComunicacion()
	{
		return HOLA;
	}
	/**
	 * Verifica si el mensaje enviado por el servidor es OK
	 * @param respuestaServ mensaje de respuesta del servidor
	 * @return True en caso de que el mensaje sea ERROR, False en caso contrario
	 */
	public static boolean verificarError(String respuestaServ)
	{
		if(respuestaServ==ERROR)
			return true;
		else
			return false;
	}
	/**
	 * Mensaje para notificar los algoritmos a usar por el servidor
	 * @return Mensaje de comunicación
	 */
	public static String mns_algoritmos()
	{
		return ALGORITMOS+SEPARADOR_PRINCIPAL+BLOWFISH+SEPARADOR_PRINCIPAL+RSA+
				SEPARADOR_PRINCIPAL+HMACSHA512;
	}
	/**
	 * Mensaje de verificación: Comunicación correcta
	 * @return mensaje de verificación
	 */
	public static String mns_OK()
	{
		return OK;
	}
	/**
	 * Mensaje de verificación: Comunicación incorrecta
	 * @return mensaje de verificación
	 */
	public static String mns_Error()
	{
		return ERROR;
	}
	/**
	 * Genera la tupla de llaves para el cliente
	 * @return Tupla de llave (privada-pública) del cliente
	 * @throws NoSuchAlgorithmException si la llave no se puede generar
	 */
	public static KeyPair llaveCliente() throws NoSuchAlgorithmException
	{
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(RSA);
		kpGen.initialize(1024);
		return kpGen.generateKeyPair();
	}
	/**
	 * Genera llave privada del servidor
	 * @param llaveCliente Tupla de llave (privada-pública) del cliente
	 * @param respServidor Respuesta del servidor
	 * @return Lllave privada del servidor
	 */
	public static SecretKey llavePrivadaServidor(KeyPair llaveCliente, String respServidor)
	{
		byte[] llaveSimetricaServidor = descifrar(llaveCliente.getPrivate(),RSA,DatatypeConverter.parseBase64Binary(respServidor));
		return new SecretKeySpec(llaveSimetricaServidor, 0, llaveSimetricaServidor.length, BLOWFISH);
	}
	/**
	 * Descrifra un mensaje con base al algortimo y llave presentados
	 * @param llave Llave para descifrar
	 * @param algoritmo Algoritmo para descifrar
	 * @param texto Texto a descrifrar
	 * @return Texto en formato byte[] descrifrado
	 */
	public static byte[] descifrar(Key llave, String algoritmo, byte[] texto)
	{
		byte[] textoClaro;
		try 
		{
			Cipher cifrado = Cipher.getInstance(algoritmo);
			cifrado.init(Cipher.DECRYPT_MODE, llave);
			textoClaro = cifrado.doFinal(texto);
		} 
		catch (Exception e) 
		{
			System.out.println("Error al descrifrar");
			return null;
		}
		return textoClaro;
	}
	/**
	 * Crifra un mensaje con base al algortimo y llave presentados
	 * @param llave Llave para cifrar
	 * @param algoritmo Algoritmo para cifrar
	 * @param texto Texto a crifrar
	 * @return Texto en formato byte[] crifrado
	 */
	public static byte[] cifrar(Key llave, String algoritmo, String texto)
	{
		byte[] textoCifrado;
		try
		{
			Cipher cifrador = Cipher.getInstance(algoritmo);
			byte[] textoByte = DatatypeConverter.parseBase64Binary(texto);

			cifrador.init(Cipher.ENCRYPT_MODE, llave);
			textoCifrado = cifrador.doFinal(textoByte);
			return textoCifrado;
		}
		catch (Exception e) 
		{
			System.out.println("Error al cifrar");
			return null;
		}
	}
	/**
	 * Descrifra un mensaje en formato HHMMM con base al algortimo y llave presentados
	 * @param llave Llave para descifrar
	 * @param algoritmo Algoritmo para descifrar
	 * @param texto Texto a descrifrar
	 * @return Texto en formato byte[] descrifrado
	 */
	public static String descifrarHHMM(Key llave, String algoritmo, byte[] texto) throws Exception
	{
		byte[] textoClaro;
		try 
		{
			Cipher cifrado = Cipher.getInstance(algoritmo);
			cifrado.init(Cipher.DECRYPT_MODE, llave);
			textoClaro = cifrado.doFinal(texto);
			return DatatypeConverter.printBase64Binary(textoClaro);
		} 
		catch (Exception e) 
		{
			System.out.println("Error al descrifrar");
			return null;
		}
	}
}
