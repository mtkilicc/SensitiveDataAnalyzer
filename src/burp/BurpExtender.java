package burp;

import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONException;
import org.json.JSONObject;


public class BurpExtender implements IBurpExtender,IScannerCheck {
	private PrintWriter mStdErr;
	private PrintWriter mStdOut;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	List<IssueList> listIssues;
	DataAnalyzer checking;

	public BurpExtender() {
		this.listIssues = new ArrayList<>(1);
		String regexCreditCard = "(?:(?<visa>4[0-9]{12}(?:[0-9]{3})?)|" +
			    "(?<mastercard>5[1-5][0-9]{14})|" +
			    "(?<discover>6(?:011|5[0-9]{2})[0-9]{12})|" +
			    "(?<amex>3[47][0-9]{13})|" +
			    "(?<diners>3(?:0[0-5]|[68][0-9])?[0-9]{11})|" +
			    "(?<jcb>(?:2131|1800|35[0-9]{3})[0-9]{11}))";
		String regexPrivateIP = "(192\\.168\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(172\\.([1][6-9]|[2][0-9]|[3][0-1])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(10\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))|(127\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5]))";
		String regexJWTToken = "eyJh([A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*)";
		String regexHtmlComment = "<!--(.*?)-->";
		String regexToken = "(token|Token)(\\:|\\=)(.*?) ";
		String regexUsername = "(username|Username)(\\:|\\=)(.*?) ";
		String regexPassword = "(password|Password)(\\:|\\=)(.*?) ";
		this.listIssues.add(new IssueList("Credit Card","Credit Card Information Found",3,regexCreditCard));
		this.listIssues.add(new IssueList("Oracle Databases","Oracle Database Error Found",3,"ORA-"));
		this.listIssues.add(new IssueList("JWT Token","JWT Token Found",2,regexJWTToken));
		this.listIssues.add(new IssueList("Private IP","Private IP Found",1,regexPrivateIP));
		this.listIssues.add(new IssueList("HTML","Html Comment Found",1,regexHtmlComment));
		this.listIssues.add(new IssueList("Token","Token Information Found",1,regexToken));
		this.listIssues.add(new IssueList("Username","Username Found",1,regexUsername));
		this.listIssues.add(new IssueList("Password","Password Found",1,regexPassword));
		this.checking = new DataAnalyzer();
	}
	
    public static void main(String[] args) {
        BurpExtender b = new BurpExtender();

    }
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks paramIBurpExtenderCallbacks) {
		BurpExtender burp = new BurpExtender();
		this.callbacks = paramIBurpExtenderCallbacks;
		this.helpers = paramIBurpExtenderCallbacks.getHelpers();
		paramIBurpExtenderCallbacks.setExtensionName("Sensitive Data Analyzer");
		this.mStdOut = new PrintWriter(paramIBurpExtenderCallbacks.getStdout(), true);
		this.mStdErr = new PrintWriter(paramIBurpExtenderCallbacks.getStderr(), true);
		this.callbacks.registerScannerCheck(this); 
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		// TODO Auto-generated method stub
		
		String match;
		List<IScanIssue> issues = new ArrayList<>(1);
		int counter = 0;
		for (int i = 0; i < this.listIssues.size(); i++) {
			List<List> listOfMixedTypes = this.checking.checkMatches(new String(baseRequestResponse.getResponse()),listIssues.get(i).getRegex(),listIssues.get(i).getName());
			List<String> listOfStrings = listOfMixedTypes.get(0);
			List<int[]> matches = listOfMixedTypes.get(1);
			 if (matches.size() > 0) {
				 String severity = "Information";
	             if (this.listIssues.get(i).getSeverity() == 1) {
	                	severity = "Low";
	                } else if (this.listIssues.get(i).getSeverity() == 2) {
	                	severity = "Medium";
	                } else if (this.listIssues.get(i).getSeverity() == 3) {
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
	                	this.mStdOut.println("Error here: " + e.getMessage());
	                	match = String.valueOf(mathcResult) + "<br> <b>Error:</b><i> " + e.getMessage().toString() + "</i>";
	                }
	                issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), this.helpers.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, (List) null, matches)}, "Sensitive Data Analyser - "+this.listIssues.get(i).getName(), "<b>This response contains:</b> " + match+ listIssues.get(i).getRegex() + "<br/><b>It's Description:</b> " + this.listIssues.get(i).getDetail(), severity));
	                //this.callbacks.addScanIssue(issues.get(counter));
	                counter++;
			 }
		}
		
		if (counter > 0) {
			return issues;
		} 
		
		return null;
		
	}


	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		// TODO Auto-generated method stub
		return null;
	}


	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		// TODO Auto-generated method stub
		return 0;
	}
}