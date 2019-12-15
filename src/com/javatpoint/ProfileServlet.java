package com.javatpoint;

import java.io.IOException;
import java.io.PrintWriter;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class ProfileServlet extends HttpServlet {
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		PrintWriter out=response.getWriter();
		
		request.getRequestDispatcher("link.html").include(request, response);
		
		Cookie ck[]=request.getCookies();
		if(ck!=null){
		 String name=ck[0].getValue();
		//Error IDS01-J. Normalize strings before validating them
		//Para prevenir inyecciones que puedan, por ejemplo, provocar vulnerabilidades cross-site scripting (XSS)
		//se desea que no se incluyan elementos como <script> que permitan ejecutar scripts maliciosos. Antes de
		//validar la entrada en busca de <,> u otros elementos habría que normalizar la cadena (transformar texto en			//unicode en sus respectivos elementos, pues "\uFE64" + "script" + "\uFE65" pasaría el validador. 
		
		 // Normalize
		name = Normalizer.normalize(name, Form.NFKC);
		// Validate
		Pattern pattern=Pattern.compile("[<>]");
		Matcher matcher=pattern.matcher(name);
		if (matcher.find()) {
			//Elemento < o > encontrado, realizar acciones deseadas (lanzar excepción, abortar login...)
			out.print("Error de usuario");
		}
		if(!name.equals("")||name!=null){
			out.print("<b>Welcome to Profile</b>");
			//name validado anteriormente
			out.print("<br>Welcome, "+name);
		}
		}else{
			out.print("Please login first");
			request.getRequestDispatcher("login.html").include(request, response);
		}
		out.close();
	}

}
