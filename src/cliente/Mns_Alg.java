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
	public static final String HOLA = "HOLA";
	public static final String OK = "OK";
	public static final String ERROR = "ERROR";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String SEPARADOR_PRINCIPAL = ":";

	public static final String BLOWFISH = "Blowfish";
	public static final String RSA = "RSA";
	public static final String HMACSHA512 = "HMACSHA512";

	public static String mns_inicComunicacion()
	{
		return HOLA;
	}

	public static boolean verificarError(String respuestaServ)
	{
		if(respuestaServ==ERROR)
			return true;
		else
			return false;
	}

	public static String mns_algoritmos()
	{
		return ALGORITMOS+SEPARADOR_PRINCIPAL+BLOWFISH+SEPARADOR_PRINCIPAL+RSA+
				SEPARADOR_PRINCIPAL+HMACSHA512;
	}

	public static String mns_OK()
	{
		return OK;
	}
	public static String mns_Error()
	{
		return ERROR;
	}

	public static KeyPair llaveCliente() throws NoSuchAlgorithmException
	{
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(RSA);
		kpGen.initialize(1024);
		return kpGen.generateKeyPair();
	}

	public static SecretKey llavePrivadaServidor(KeyPair llaveCliente, String respServidor)
	{
		byte[] llaveSimetricaServidor = descifrar(llaveCliente.getPrivate(),RSA,DatatypeConverter.parseBase64Binary(respServidor));
		return new SecretKeySpec(llaveSimetricaServidor, 0, llaveSimetricaServidor.length, BLOWFISH);
	}

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
	
	public static byte[] cifrar(Key llave, String algoritmo, String texto)
	{
		byte[] textoCifrado;
		try
		{
			Cipher cifrador = Cipher.getInstance(algoritmo);
			byte[] textoClaro = texto.getBytes();
			
			cifrador.init(Cipher.ENCRYPT_MODE, llave);
			textoCifrado = cifrador.doFinal(textoClaro);
			return textoCifrado;
		}
		catch (Exception e) 
		{
			System.out.println("Error al cifrar");
			return null;
		}
	}
	
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
