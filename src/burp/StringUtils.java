package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtils {

	/*
	 General Strings 
	 */
	static String userDir = System.getProperty("user.dir");
	static String dbName = "issues.db";
	static String regexName = "/issueList.json";
	static String createTable = "CREATE TABLE IF NOT EXISTS issues(scantype TEXT NOT NULL,payload TEXT NOT NULL,regex TEXT NOT NULL,name TEXT NOT NULL UNIQUE,description TEXT NOT NULL,severity TEXT NOT NULL,confidence TEXT NOT NULL);";
	static String addIssue = "INSERT INTO issues VALUES(_replace_);";
	static String checkName =  "SELECT name FROM issues WHERE name=\"_replace_\";";
	static String getPassiveIssues = "SELECT * FROM issues WHERE scantype=\"Passive\"";
	static String getActiveIssues = "SELECT * FROM issues WHERE scantype=\"Active\"";
	static String [] jsonVariables = {"ScanType", "Payload", "Regex", "Name", "Description", "Severity", "Confidence"};
	/*
	 Info Strings 
	 */
	static String info_1 = "Your regexList.txt is loaded.";
	
	/*
	 Error Strings 
	 */
	static String errorDuplicateIssueName = "Your issue name insterted before, check issue name.";
	static String error_1 = "You need to add file under user directory and the file is must to named regexList.txt.\\nYour user director is: ";
	static String errorEmptyIssueList = "Issue List couldn't create. Your regexList.json may be empty or not inclued valid context.";
	

	
	static String createDescriptionIssue(List<String> matchArray, String description) {
		String result = "<br/> <br/> <b>Maches Details is:</b> <ul> ";
		
		for (int i = 0; i < matchArray.size(); i++) {
			result = result + "<li>" + matchArray.get(i).replaceAll("<","&lt;").replaceAll(">","&gt;") + "</li>"; 
		}
		
		result = result + "</ul>";
		result = result + "<br/><b>It's Description:</b>" + description;
		
		return result;
	}
	
	
	static List<List> checkMatches(String response, String match) {
		List<List> listOfMixedTypes = new ArrayList<>();
		List<String> listOfStrings = new ArrayList<>();
		List<int[]> matches = new ArrayList<>();
		String mydata = response;
        Pattern pattern = Pattern.compile(match);
        Matcher matcher = pattern.matcher(mydata);
        
        while (matcher.find()) {
            matches.add(new int[]{matcher.start(0), matcher.end(0)});
            listOfStrings.add(response.substring(matcher.start(0),matcher.end(0)));
        }
        
        listOfMixedTypes.add(listOfStrings);
        listOfMixedTypes.add(matches);
        
		return listOfMixedTypes;
	}
	
}
