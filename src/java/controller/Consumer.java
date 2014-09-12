/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package controller;

/**
 *
 * @author Kennedy
 */
import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import controller.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.rodrigoramalho.openid.autenticacao.ResultType;
import org.rodrigoramalho.openid.beans.User;

/**
 * 
 * @author rodrigoramalho
 * 		   hodrigohamalho@gmail.com
 *
 */
public class Consumer{
    // the authentication responses from the OpenID provider
    private static String GOOGLE_USER_SUPPLIED = "https://www.google.com/accounts/o8/id";

    private static final String GOOGLE_ENDPOINT = "https://www.google.com";
    private static final String YAHOO_ENDPOINT = "https://me.yahoo.com"; 
	
    public ConsumerManager manager;

    public Consumer() throws ConsumerException
    {
        manager = new ConsumerManager();
    }

    public ResultType authRequest(HttpServletRequest request, HttpServletResponse response, ServletContext servletContext) throws IOException{
        try{
        	// realm Ž a url da aplica‹o + porta ex: http://localhost:8080
    		String realm = getRealm(request);
    		// Definimos a url a qual o google dever‡ retornar ap—s autenticar o usu‡rio
    		String returnToUrl = new StringBuffer(realm).append(request.getContextPath()) + "/Auth";
        	
    		// "descobre" o OpenID do fornecedor
            List discoveries = manager.discover(GOOGLE_USER_SUPPLIED);

            // Tentativa de se conectar com o provedor OpenID 
            // e acessar um endpoint service pra se autenticar
            DiscoveryInformation discovered = manager.associate(discoveries);

            // ObtŽm a requisi‹o de autoriza‹o que ser‡ mandada para o provedor OpenID 
            AuthRequest authReq = manager.authenticate(discovered, returnToUrl);
            
            // Informa quais atributos dever‹o ser 'requeridos'
            FetchRequest fetch = mountFetchRequest(); 
            authReq.addExtension(fetch);
            
            authReq.setRealm(realm);
            
            // coloca o objeto discovered na sess‹o do usu‡rio
            request.getSession().setAttribute("discovered", discovered);
            request.getSession().setAttribute("checkResponse", true);
            
            // Encaminha para a p‡gina de autentica‹o do google
            response.sendRedirect(authReq.getDestinationUrl(true));
        }
        catch (OpenIDException e){
          e.printStackTrace();
		}

        return ResultType.REDIRECT_TO_OPENID_PROVIDER_FAILURE;
    }

    private String getRealm(HttpServletRequest request) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
