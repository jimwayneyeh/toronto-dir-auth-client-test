package org.twgogo.jimwayne.toronto.directory.client;

import java.security.SecureRandom;
import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class App {
	private static SecureRandom RANDOM = new SecureRandom();
	
    public static void main( String[] args ) {
    	Logger log = LoggerFactory.getLogger("Main");
    	
    	String adminAccount = null;
    	String adminPassword = null;
    	String hostAddr = null;
    	
    	// ------------------------------- //
    	//       Parse the argument.       //
    	// ------------------------------- //
    	for(int i=0 ; i<args.length ; ++i) {
    		String currentArg = args[i];
    		
    		switch(currentArg) {
    			case "-u":
    				adminAccount = args[++i];
    				break;
    			case "-p":
    				adminPassword = args[++i];
    				break;
    			case "-h":
    				hostAddr = args[++i];
    				break;
    		}
    	}
    	
    	Authentication auth = new Authentication(hostAddr);
    	
    	// Login as admin.
    	String adminTicket = auth.login(null, adminAccount, adminPassword);
    	log.info("Get directory ticket {}.", adminTicket);
    	
    	// Create a tenant.
    	String tenantName = "test" + RANDOM.nextInt();
    	log.info("Try to create a tenant with name '{}'.", tenantName);
    	String tenantId = auth.createTenant(adminTicket, tenantName);
    	log.info("The ID of created tenant is {}.", tenantId);
    	
    	// Create an user in the tenant.
    	String username = "user";
    	String password = "qwer";
    	log.info("Try to create an user {} in tenant {}.", username, tenantName);
    	auth.createUser(adminTicket, tenantId, username, password, 
    			String.valueOf(RANDOM.nextLong()), String.valueOf(RANDOM.nextLong()), String.valueOf(RANDOM.nextLong()));
    }
}
