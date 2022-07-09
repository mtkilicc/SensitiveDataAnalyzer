package burp;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

import org.json.JSONException;
import org.json.JSONObject;



public class testRun {

	static IssueList issue;
	static List<IssueList> listIssues;
	static DataAnalyzer checking;

	
	public static void main(String[] args) throws JSONException, IOException {
		// TODO Auto-generated method stub
		
		issue = new IssueList();
		try {
			listIssues = issue.generateIssue("/Applications/Burp Suite Professional.app/Contents/Resources/app/regexList.txt");
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		checking = new DataAnalyzer();
		String response = "The Error Here: ORA-12345\n Details  the credit card is not valid: 5571135571135575\n\nThe Error Here: ORA-123\\n Details  the credit card is not valid: 5571135571131234 The Error Here: ORA-12345\\n Details  the credit card is not valid: 5571135571135575\\n\\nThe Error Here: ORA-12345\\\\n Details  the credit card is not valid: 5571135571131234  \n"
				+ "Token: 12312312312312 jjhjhlhljhjlh\n"
				+ "TokenDeneme Username: 123123 \n"
				+ "127.0.0.3\npassword: 123123\n"
				+ "10.34.0.123\n"
				+ "172.75.123.22\n"
				+ "192.168.0.0\n"
				+ "111.111.111.111\n"
				+ "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
				+ "email@emil.com";
		System.out.println("Start");
		
		String match;
		List<IScanIssue> issues = new ArrayList<>(1);
		int counter = 0;
		if (listIssues != null) {
			
		System.out.println("Size of list: " + listIssues.size());
		for (int i = 0; i < listIssues.size(); i++) {
			System.out.println("In List");
			System.out.println("Scan Type: "+ listIssues.get(i).getScanType());
			if (listIssues.get(i).getScanType().equals("Active") || listIssues.get(i).getScanType().equals("Multiple")) {
				System.out.println("Here");
			
			List<List> listOfMixedTypes = checking.checkMatches(new String(response),listIssues.get(i).getRegex(),listIssues.get(i).getName());
			List<String> listOfStrings = listOfMixedTypes.get(0);
			List<int[]> matches = listOfMixedTypes.get(1);
			 if (matches.size() > 0) {
				 System.out.println("Found Matches steps");
				 String severity = "Information";
	             if (listIssues.get(i).getSeverity() == 1) {
	                	severity = "Low";
	                } else if (listIssues.get(i).getSeverity() == 2) {
	                	severity = "Medium";
	                } else if (listIssues.get(i).getSeverity() == 3) {
	                	severity = "High";
	                }
	             String mathcResult = "";
	                try {
	                	mathcResult = "<br/> <br/> <b>Maches Details is:</b> <ul> ";
	                    for (int j = 0; j < matches.size(); j++) {
	                    	String result = listOfStrings.get(j);
	                    	
	                    	mathcResult = String.valueOf(mathcResult) + "<li>" + result + "</li>";
	                    }
	                    match = String.valueOf(mathcResult) + "</ul>";
	                } catch (Exception e) {
	                	match = String.valueOf(mathcResult) + "<br> <b>Error:</b><i> " + e.getMessage().toString() + "</i>";
	                }
	                System.out.println("Add steps");
	                System.out.println(counter+". Matches:" + match);
	                counter++;
			 }
		}
		}
		}
		

		
		
	}

}
