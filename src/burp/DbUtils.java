package burp;

import java.io.PrintWriter;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DbUtils {
	
	
    private Connection connect() throws SQLException {
        Connection conn = null;
        conn = DriverManager.getConnection("jdbc:sqlite:"+StringUtils.userDir+"/"+StringUtils.dbName);
        return conn;
    }
	
	public void generateDB() throws SQLException {
		Connection conn = connect();
	    Statement stmt  = conn.createStatement();
	    stmt.execute(StringUtils.createTable); 
	}
	
	public void insertValue(String insertData, String insertName, PrintWriter mStdErr) throws SQLException {
		 Connection conn = connect();
         Statement stmt  = conn.createStatement();
         ResultSet resultQuery  = stmt.executeQuery(StringUtils.checkName.replace("_replace_",insertName)); 
        
         if (!resultQuery.next()) {
           	 stmt.execute(insertData); 

         } else {
        	 mStdErr.println(StringUtils.errorDuplicateIssueName+"\t"+insertName);
         }
         
         resultQuery.close();
      	 stmt.close();
	}
	
	public List<String[]> getIssues(String issueType) throws SQLException {
		
		Connection conn = connect();
        Statement stmt  = conn.createStatement();
        ResultSet resultQuery  = null; 
        List<String[]> resultList = new ArrayList<String[]>();;
        String[] resultArray;
        switch (issueType) {
		case "Passive":
			resultQuery = stmt.executeQuery(StringUtils.getPassiveIssues);
			break;
		case "Active":
			resultQuery = stmt.executeQuery(StringUtils.getActiveIssues);
			break;
		
		}     
        while (resultQuery.next()) {
        	resultArray  = new String[7];
        	for (int i = 0; i < StringUtils.jsonVariables.length; i++) {
        		resultArray[i] = resultQuery.getString(StringUtils.jsonVariables[i]);
			}
        	resultList.add(resultArray);
        }
        
        return resultList;
	}
	

}
