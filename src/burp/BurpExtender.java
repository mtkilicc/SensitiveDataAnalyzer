package burp;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestInputStream;
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
	private IssueList issue;
	private byte[]  md5hash;


    public static void main(String[] args) {
       // BurpExtender b = new BurpExtender();

    }
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks paramIBurpExtenderCallbacks) {
		this.callbacks = paramIBurpExtenderCallbacks;
		this.helpers = paramIBurpExtenderCallbacks.getHelpers();
		paramIBurpExtenderCallbacks.setExtensionName("Sensitive Data Analyzer");
		this.mStdOut = new PrintWriter(paramIBurpExtenderCallbacks.getStdout(), true);
		this.mStdErr = new PrintWriter(paramIBurpExtenderCallbacks.getStderr(), true);
		//BurpExtender burp = new BurpExtender();
		this.callbacks.registerScannerCheck(this);
		this.issue = new IssueList();
		this.md5hash = null;
		generateIssue();
		this.checking = new DataAnalyzer();
	}
	
	public byte[] calculateMd5(String file) throws NoSuchAlgorithmException, IOException {
		
		MessageDigest md = MessageDigest.getInstance("MD5");
		InputStream is = Files.newInputStream(Paths.get(file));
		DigestInputStream dis = new DigestInputStream(is, md);
		return md.digest();
	}
	
	public void checkFileChange() {
		
		try {
			byte[] digest = calculateMd5(System.getProperty("user.dir")+"/regexList.txt");
			if (this.md5hash != digest) {
				generateIssue();
			} 
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();

		}
	}
	
	public void generateIssue() {
		try {
			this.listIssues = issue.generateIssue(System.getProperty("user.dir")+"/regexList.txt");
			mStdOut.println("Your regexList.txt is loaded.");
			this.md5hash = calculateMd5(System.getProperty("user.dir")+"/regexList.txt");
		} catch (Exception e) {
			// TODO: handle exception
			mStdErr.println("Error: " + e);
			mStdErr.println("You need to add file under user directory and the file is must to named regexList.txt.\nYour user director is: " + System.getProperty("user.dir"));
		}
	}
	
	public List<IScanIssue> findIssues(IHttpRequestResponse baseRequestResponse, String scanType){
		
		String match;
		List<IScanIssue> issues = new ArrayList<>(1);
		for (int i = 0; i < this.listIssues.size(); i++) {
			
			if (listIssues.get(i).getScanType().equals(scanType) || listIssues.get(i).getScanType().equals("Multiple") ) {
				
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
	                    	result = result.replaceAll("<","&lt;");
	                    	result = result.replaceAll(">","&gt;");
	                    	mathcResult = String.valueOf(mathcResult) + "<li>" + result + "</li>";
	                    }
	                    match = String.valueOf(mathcResult) + "</ul>";
	                } catch (Exception e) {
	                	this.mStdOut.println("Error here: " + e.getMessage());
	                	match = String.valueOf(mathcResult) + "<br> <b>Error:</b><i> " + e.getMessage().toString() + "</i>";
	                }
	                
	                String desc = String.valueOf(match) + "<br/><b>It's Description:</b> " + this.listIssues.get(i).getDetail();
	                //mStdOut.println(counter + ". The result: " + match);
	                issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), this.helpers.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, (List) null, matches)}, "Sensitive Data Analyser - "+this.listIssues.get(i).getName(), desc , severity));
	                //this.callbacks.addScanIssue(issues.get(counter));
			 }
		}
			}
		return issues;
		
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		// TODO Auto-generated method stub
		
		checkFileChange();
		
		if (this.listIssues.size() == 0) {
			mStdErr.println("Issue List couldn't create. Your regexList.txt may be empty or not inclued valid context.\nEach line need to seperate 4 columns such as <Found name>;<Found Details>;<Found Severity(0,1,2,3)>;<Found Regex>;<Found ScanType(Passive,Active,Multiple)>");
			return null;
		} else {
			List<IScanIssue> issues = findIssues(baseRequestResponse,"Passive");
			if (issues.size() > 0) {
				return issues;
			} else {
				return null;
			}
		}
		
		
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		
		checkFileChange();
		// TODO Auto-generated method stub
		if (this.listIssues.size() == 0) {
			mStdErr.println("Issue List couldn't create. Your regexList.txt may be empty or not inclued valid context.\nEach line need to seperate 4 columns such as <Found name>;<Found Details>;<Found Severity(0,1,2,3)>;<Found Regex>;<Found ScanType(Passive,Active,Multiple)>");
			return null;
		} else {
			List<IScanIssue> issues = findIssues(baseRequestResponse,"Active");
			if (issues.size() > 0) {
				return issues;
			} else {
				return null;
			}
		}
	}


	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		// TODO Auto-generated method stub
		return 0;
	}
}