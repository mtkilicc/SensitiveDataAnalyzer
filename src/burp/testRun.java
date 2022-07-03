package burp;

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

	
	public static void main(String[] args) throws JSONException {
		// TODO Auto-generated method stub
		
		listIssues = new ArrayList<>(1);
		String regexCreditCard = "(?:(?<visa>4[0-9]{12}(?:[0-9]{3})?)|" +
			    "(?<mastercard>5[1-5][0-9]{14})|" +
			    "(?<discover>6(?:011|5[0-9]{2})[0-9]{12})|" +
			    "(?<amex>3[47][0-9]{13})|" +
			    "(?<diners>3(?:0[0-5]|[68][0-9])?[0-9]{11})|" +
			    "(?<jcb>(?:2131|1800|35[0-9]{3})[0-9]{11}))";
		String regexPrivateIP = "(192\\.168\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(172\\.([1][6-9]|[2][0-9]|[3][0-1])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(10\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(127\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))";
		String regexJWTToken = "eyJh([A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*)";
		listIssues.add(new IssueList("Credit Card","Credit Card Information Found",3,regexCreditCard));
		listIssues.add(new IssueList("Oracle Databases","Oracle Error Found",1,"ORA-"));
		listIssues.add(new IssueList("JWT Token","JWT Token Found",2,regexJWTToken));
		listIssues.add(new IssueList("Private IP","Private IP Found",2,regexPrivateIP));
		checking = new DataAnalyzer();
		String response = "The Error Here: ORA-12345\n Details  the credit card is not valid: 5571135571135575\n\nThe Error Here: ORA-12345\\n Details  the credit card is not valid: 5571135571131234 The Error Here: ORA-12345\\n Details  the credit card is not valid: 5571135571135575\\n\\nThe Error Here: ORA-12345\\\\n Details  the credit card is not valid: 5571135571131234  \n"
				+ "Token: 12312312312312\n"
				+ "TokenDeneme\n"
				+ "127.0.0.3\n"
				+ "10.34.0.123\n"
				+ "172.75.123.22\n"
				+ "192.168.0.0\n"
				+ "111.111.111.111\n"
				+ "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c ";
		System.out.println("Start");
		
		String match;
		List<IScanIssue> issues = new ArrayList<>(1);
		int counter = 0;
		for (int i = 0; i < listIssues.size(); i++) {
			System.out.println("In List");
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
	                //issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), this.helpers.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, (List) null, matches)}, "Sensitive Data Analyser - "+listIssues.get(i).getName(), "<b>This response contains:</b> " + listIssues.get(i).getRegex() + "<br/><b>It's Description:</b> " + listIssues.get(i).getDetail() + match, severity));
				 counter++;
			 }
		}
		

		
		
	}

}
