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
		//Para comprobar que un método se ha realizado correctamente, estos suelen devolver valores que nos sirven para
		//prevenir futuros errores, como por ejemplo hacer referencias a variables nulas o no inicializadas
		//En este caso, si no se puede crear correctamente el dispatcher el método include operaría sobre un objeto nulo
		//o no inicializado, lo que podría suponer problemas
		request.getRequestDispatcher("link.html").include(request, response);
		
		//Error IDS01-J. Normalize strings before validating them
		//Para prevenir inyecciones que puedan, por ejemplo, provocar vulnerabilidades cross-site scripting (XSS)
		//se desea que no se incluyan elementos como <script> que permitan ejecutar scripts maliciosos. Antes de
		//validar la entrada en busca de <,> u otros elementos habría que normalizar la cadena (transformar texto en
		//unicode en sus respectivos elementos, pues "\uFE64" + "script" + "\uFE65" pasaría el validador. 
		
		String name=request.getParameter("name");
		// Normalize
		name = Normalizer.normalize(name, Form.NFKC);
		// Validate
		Pattern pattern=Pattern.compile("[<>]");
		Matcher matcher=pattern.matcher(name);
		if (matcher.find()) {
			//Elemento < o > encontrado, realizar acciones deseadas (lanzar excepción, abortar login...)
			out.print("Error de usuario");
		}
		 
		//Guardando la contraseña en un objeto String habría que esperar al recolector de basura para ser eliminado,
		//por lo que es mejor opción guardarla en un array de caracteres para que podamos limpiarla manualmente.
		//String password=request.getParameter("password");
		
		//Como en la validación se ha encontrado otro error que para ser subsanado se necesita tener la contraseña
		//como un array de bytes, la convertimos aquí en lugar del array de caracteres
		//char [] password=request.getParameter("password").toCharArray();
		byte [] password=request.getParameter("password").getBytes();
		
		// No incumple EXP02-J porque en JAVA los Strings son objetos de la clase String y no un array de caracteres
		// Es un error almacenar las contraseñas en claro. Aunque el cliente introduzca la contraseña en claro, el
		// servidor debería almacenar únicamente los hash de las contraseñas, de modo que si el hash de la contraseña
		// introducida por el usuario coincide con el hash que tenemos almacenado para ese usuario admitiremos el login
		MessageDigest messageDigest=MessageDigest.getInstance("SHA-1");
		
		//El método digest toma como parámetro un array de tipo byte (byte[]) por lo que necesitamos la contraseña en
		//tipo byte[]
		byte [] hash=messageDigest.digest(password);
		
		//if(password.equals("admin123")){
		//Para no incumplir EXP02-J no podemos comparar dos arrays mediante el método equals, ya que compara la referencia
		//de ambos objetos. Para comparar 2 arrays se puede usar el operador lógico == o la función estática equals de la
		//clase Arrays
		
		//SOLO COMO EJEMPLO. Para poder validar correctamente habría que leer el hash de verdad de algún sitio seguro,
		//como una base de datos o un fichero encriptado. Si se guardase en una base de datos habría que realizar las
		//acciones pertinentes para prevenir la inyección SQL
		byte [] userPassword = {0};
		//Se compara el hash de la contraseña del usuario con el hash guardado en el sistema
		if(hash==userPassword){
			out.print("You are successfully logged in!");
			
			//name validado anteriormente
			out.print("<br>Welcome, "+name);
			
			Cookie ck=new Cookie("name",name);
			
			//addCookie no devuelve ningún valor (tipo void), por lo tanto no incumple EXP00-J.
			response.addCookie(ck);
			
		}else{
			out.print("sorry, username or password error!");
			// EXP00-J. Do not ignore values returned by methods
			request.getRequestDispatcher("login.html").include(request, response);
		}
		//Limpiar la contraseña y su hash una vez validada
		//Arrays.fill(password, ' ');
		//Se sabe que 0 es un valor válido del typo byte
		Arrays.fill(password, (byte) 0);
		Arrays.fill(hash, (byte) 0);
		out.close();
	}

}
