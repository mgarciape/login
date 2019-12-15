package com.javatpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet extends HttpServlet {
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		response.setContentType("text/html");
		
		PrintWriter out=response.getWriter();
		
		//EXP00-J. Do not ignore values returned by methods
		//Para comprobar que un m�todo se ha realizado correctamente, estos suelen devolver valores que nos sirven para
		//prevenir futuros errores, como por ejemplo hacer referencias a variables nulas o no inicializadas
		//En este caso, si no se puede crear correctamente el dispatcher el m�todo include operar�a sobre un objeto nulo
		//o no inicializado, lo que podr�a suponer problemas
		request.getRequestDispatcher("link.html").include(request, response);
		
		//Error IDS01-J. Normalize strings before validating them
		//Para prevenir inyecciones que puedan, por ejemplo, provocar vulnerabilidades cross-site scripting (XSS)
		//se desea que no se incluyan elementos como <script> que permitan ejecutar scripts maliciosos. Antes de
		//validar la entrada en busca de <,> u otros elementos habr�a que normalizar la cadena (transformar texto en
		//unicode en sus respectivos elementos, pues "\uFE64" + "script" + "\uFE65" pasar�a el validador. 
		
		String name=request.getParameter("name");
		// Normalize
		name = Normalizer.normalize(name, Form.NFKC);
		// Validate
		Pattern pattern=Pattern.compile("[<>]");
		Matcher matcher=pattern.matcher(name);
		if (matcher.find()) {
			//Elemento < o > encontrado, realizar acciones deseadas (lanzar excepci�n, abortar login...)
			out.print("Error de usuario");
		}
		 
		//Guardando la contrase�a en un objeto String habr�a que esperar al recolector de basura para ser eliminado,
		//por lo que es mejor opci�n guardarla en un array de caracteres para que podamos limpiarla manualmente.
		//String password=request.getParameter("password");
		
		//Como en la validaci�n se ha encontrado otro error que para ser subsanado se necesita tener la contrase�a
		//como un array de bytes, la convertimos aqu� en lugar del array de caracteres
		//char [] password=request.getParameter("password").toCharArray();
		byte [] password=request.getParameter("password").getBytes();
		
		// No incumple EXP02-J porque en JAVA los Strings son objetos de la clase String y no un array de caracteres
		// Es un error almacenar las contrase�as en claro. Aunque el cliente introduzca la contrase�a en claro, el
		// servidor deber�a almacenar �nicamente los hash de las contrase�as, de modo que si el hash de la contrase�a
		// introducida por el usuario coincide con el hash que tenemos almacenado para ese usuario admitiremos el login
		MessageDigest messageDigest=MessageDigest.getInstance("SHA-1");
		
		//El m�todo digest toma como par�metro un array de tipo byte (byte[]) por lo que necesitamos la contrase�a en
		//tipo byte[]
		byte [] hash=messageDigest.digest(password);
		
		//if(password.equals("admin123")){
		//Para no incumplir EXP02-J no podemos comparar dos arrays mediante el m�todo equals, ya que compara la referencia
		//de ambos objetos. Para comparar 2 arrays se puede usar el operador l�gico == o la funci�n est�tica equals de la
		//clase Arrays
		
		//SOLO COMO EJEMPLO. Para poder validar correctamente habr�a que leer el hash de verdad de alg�n sitio seguro,
		//como una base de datos o un fichero encriptado. Si se guardase en una base de datos habr�a que realizar las
		//acciones pertinentes para prevenir la inyecci�n SQL
		byte [] userPassword = {0};
		//Se compara el hash de la contrase�a del usuario con el hash guardado en el sistema
		if(hash==userPassword){
			out.print("You are successfully logged in!");
			
			//name validado anteriormente
			out.print("<br>Welcome, "+name);
			
			Cookie ck=new Cookie("name",name);
			
			//addCookie no devuelve ning�n valor (tipo void), por lo tanto no incumple EXP00-J.
			response.addCookie(ck);
			
		}else{
			out.print("sorry, username or password error!");
			// EXP00-J. Do not ignore values returned by methods
			request.getRequestDispatcher("login.html").include(request, response);
		}
		//Limpiar la contrase�a y su hash una vez validada
		//Arrays.fill(password, ' ');
		//Se sabe que 0 es un valor v�lido del typo byte
		Arrays.fill(password, (byte) 0);
		Arrays.fill(hash, (byte) 0);
		out.close();
	}

}
