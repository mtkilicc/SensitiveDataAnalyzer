package burp;

import java.io.File;
import java.io.PrintWriter;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
public class DbUtils {
	
	private StringUtils strUtil = new StringUtils();
	
	
    private Connection connect() throws SQLException {
        Connection conn = null;
        File theDir = new File(strUtil.userDir+"/SensitiveDataAnalyzer/");
        if (!theDir.exists()){
            theDir.mkdirs();
        }
        conn = DriverManager.getConnection("jdbc:sqlite:"+strUtil.dbPath);
        return conn;
    }
	
    
	public void generateDB() throws SQLException {
		Connection conn = connect();
	    Statement stmt  = conn.createStatement();
	    stmt.execute(strUtil.createTable); 
	}
	
	
	public void insertValue(String insertData, String insertName, PrintWriter mStdErr) throws SQLException {
		 Connection conn = connect();
         Statement stmt  = conn.createStatement();
         ResultSet resultQuery  = stmt.executeQuery(strUtil.checkName.replace("_replace_",insertName)); 
         if (!resultQuery.next()) {
           	 stmt.execute(insertData); 

         } else {
        	 mStdErr.println(strUtil.errorDuplicateIssueName+"\t"+insertName);
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
			resultQuery = stmt.executeQuery(strUtil.getPassiveIssues);
			break;
		case "Active":
			resultQuery = stmt.executeQuery(strUtil.getActiveIssues);
			break;
		}     
        while (resultQuery.next()) {
        	resultArray  = new String[7];
        	for (int i = 0; i < strUtil.jsonVariables.length; i++) {
        		resultArray[i] = resultQuery.getString(strUtil.jsonVariables[i]);
			}
        	resultList.add(resultArray);
        }
        return resultList;
	}
	
	
	public void removeIssuteTable() throws SQLException {
		Connection conn = connect();
	    Statement stmt  = conn.createStatement();
	    stmt.execute(strUtil.removeIssues);
	    stmt.execute(strUtil.createTable);
	}

}
