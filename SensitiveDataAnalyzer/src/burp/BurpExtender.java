package burp;


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.json.*;


public class BurpExtender implements IBurpExtender,IScannerCheck {
	private PrintWriter mStdErr;
	private PrintWriter mStdOut;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	List<Issue> passiveIssues;
	List<Issue> activeIssues;
	DbUtils dbRunner;
	private byte[]  md5hash;


    public static void main(String[] args) {
    	
    }
    
	
	public void registerExtenderCallbacks(IBurpExtenderCallbacks paramIBurpExtenderCallbacks) {
		this.callbacks = paramIBurpExtenderCallbacks;
		this.helpers = paramIBurpExtenderCallbacks.getHelpers();
		paramIBurpExtenderCallbacks.setExtensionName("Sensitive Data Analyzer");
		this.mStdOut = new PrintWriter(paramIBurpExtenderCallbacks.getStdout(), true);
		this.mStdErr = new PrintWriter(paramIBurpExtenderCallbacks.getStderr(), true);
		this.callbacks.registerScannerCheck(this);
		dbRunner  = new DbUtils();
		this.passiveIssues = new ArrayList<Issue>();
		this.activeIssues = new ArrayList<Issue>();
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			mStdErr.println("forName: " + e.getMessage());
		}
		try {
			dbRunner.generateDB();	
		} catch (Exception e) {
			// TODO Auto-generated catch block
			mStdErr.println("generateDB:" + e.getMessage());
		}
		try {
			createIssues(StringUtils.userDir+StringUtils.regexName);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			mStdErr.println("createIssues:" + e.getMessage());
		}
		try {
			generateIssuesList();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			mStdErr.println("generateIssuesList:" + e.getMessage());
		}
		try {
			//calculateMd5(StringUtils.userDir+StringUtils.regexName);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			mStdErr.println("calculateMd5:" + e.getMessage());
		}
	}
	
	
	public void createIssues(String fileName) throws FileNotFoundException, JSONException, SQLException {
		InputStream inputstream = new FileInputStream(fileName);
		JSONTokener tokener = new JSONTokener(inputstream);
		JSONObject issueList = new JSONObject(tokener);
		String insertValue;
		String insertName;
		JSONArray issueArray = issueList.getJSONArray("data");
		for (int i = 0; i < issueArray.length(); i++) {
			insertValue = "";
			for (int j = 0; j < StringUtils.jsonVariables.length; j++) {
				insertValue += "\"" + issueArray.getJSONObject(i).getString(StringUtils.jsonVariables[j]);
				if (StringUtils.jsonVariables.length-1 == j) {
					insertValue += "\"";
				} else {
					insertValue += "\",";
				}
			}
			insertName = issueArray.getJSONObject(i).getString("Name");
			dbRunner.insertValue(StringUtils.addIssue.replace("_replace_",insertValue),insertName,this.mStdErr);
		}
	}
	
	
	public void generateIssuesList() throws SQLException{
		
	        List<String[]> passiveArray = dbRunner.getIssues("Passive");
	        List<String[]> activeArray = dbRunner.getIssues("Active");
	        
	        for (int i = 0; i < passiveArray.size(); i++) {
	        	this.passiveIssues.add(new Issue(passiveArray.get(i)[1],passiveArray.get(i)[2],passiveArray.get(i)[3],passiveArray.get(i)[4],passiveArray.get(i)[5],passiveArray.get(i)[6]));
	        }
	        for (int i = 0; i < activeArray.size(); i++) {
	        	this.activeIssues.add(new Issue(activeArray.get(i)[1],activeArray.get(i)[2],activeArray.get(i)[3],activeArray.get(i)[4],activeArray.get(i)[5],activeArray.get(i)[6]));
			}
	}
	
	
	public byte[] calculateMd5(String file) throws NoSuchAlgorithmException, IOException {
		
		MessageDigest md = MessageDigest.getInstance("MD5");
		InputStream is = Files.newInputStream(Paths.get(file));
		DigestInputStream dis = new DigestInputStream(is, md);
		return md.digest();
	}
	
	
	public void checkFileChange() {
		
		try {
			byte[] digest = calculateMd5(StringUtils.userDir+StringUtils.regexName);
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
			generateIssuesList();
			this.md5hash = calculateMd5(StringUtils.userDir+StringUtils.regexName);
		} catch (Exception e) {
			// TODO: handle exception
			mStdErr.println(StringUtils.error_1 + StringUtils.userDir);
		}
	}
	
	
	public List<IScanIssue> findIssues(IHttpRequestResponse baseRequestResponse, List<Issue> issueList){
		
		List<IScanIssue> issues = new ArrayList<>();
		for (int i = 0; i < issueList.size(); i++) {
			List<List> listOfMixedTypes = StringUtils.checkMatches(new String(baseRequestResponse.getResponse()),issueList.get(i).getRegex());
			List<String> listOfStrings = listOfMixedTypes.get(0);
			List<int[]> matches = listOfMixedTypes.get(1);
			 if (matches.size() > 0) {
				 List<String> matchArray = new ArrayList<>();
	                try {
	                    for (int j = 0; j < matches.size(); j++) {
	                    	matchArray.add(listOfStrings.get(j));
	                    }
	                    
	                } catch (Exception e) {
	                	this.mStdErr.println("Find Issues error is: " + e.getMessage());
	                }
	                String severity = issueList.get(i).getSeverity();
	                String desc = StringUtils.createDescriptionIssue(matchArray,issueList.get(i).getDescription()); 
	                issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), this.helpers.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, (List) null, matches)}, "Sensitive Data Analyser - "+issueList.get(i).getName(), desc , severity,issueList.get(i).getCofidence()));
			 }
			}
		return issues;
	}
	

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		// TODO Auto-generated method stub
		
		//checkFileChange();
		
		if (!this.callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
			return null;
		}

		
		if (this.passiveIssues.size() == 0) {
			mStdErr.println(StringUtils.errorEmptyIssueList);
			return null;
		} else {
			
			List<IScanIssue> issues = findIssues(baseRequestResponse,this.passiveIssues);
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
		
		//checkFileChange();
		
		if (!this.callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
			return null;
		}
		
		if (this.activeIssues.size() == 0) {
			mStdErr.println(StringUtils.errorEmptyIssueList);
			return null;
		} else {
			List<IScanIssue> issues = new ArrayList<>();
			for (int i = 0; i < activeIssues.size(); i++) {
				byte[] checkRequest = insertionPoint.buildRequest(java.net.URLDecoder.decode(activeIssues.get(i).getPayload()).getBytes());
				IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
		                baseRequestResponse.getHttpService(), checkRequest);
				List<Issue> control = new ArrayList<>();
				control.add(activeIssues.get(i));
				issues.addAll(findIssues(baseRequestResponse,control));
			}
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
		 if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
	         return -1;
	     else
	    	 return 0;
	}
}

