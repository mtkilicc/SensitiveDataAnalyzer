package burp;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DataAnalyzer {
	
	
	public DataAnalyzer() {
	}
	
	public List<List> checkMatches(String response, String match, String name) {
		
		List<List> listOfMixedTypes = new ArrayList<List>();
		List<String> listOfStrings = new ArrayList<>();
		List<int[]> matches = new ArrayList<>();
		String mydata = response;
        Pattern pattern = Pattern.compile(match);
        Matcher matcher = pattern.matcher(mydata);
        while (matcher.find()) {
        	int  counter = 0;
            matches.add(new int[]{matcher.start(0), matcher.end(0)});
           
            if(name.equals("Credit Card"))  {
            	if (matcher.group("visa") != null) {
            		listOfStrings.add("visa: " + matcher.group(counter));
				} else if (matcher.group("mastercard") != null) {
					listOfStrings.add("mastercard:" + matcher.group(counter));
				} else if (matcher.group("discover") != null) {
					listOfStrings.add("discover: " + matcher.group(counter));
				} else if (matcher.group("amex") != null) {
					listOfStrings.add("amex: " + matcher.group(counter));
				} else if (matcher.group("diners") != null) {
					listOfStrings.add("diners: " + matcher.group(counter));
				} else if (matcher.group("jcb") != null) {
					listOfStrings.add("jcb: " + matcher.group(counter));
				}
            }
            else {
            	 listOfStrings.add(matcher.group(counter));
            }
            counter++;
        }
		
        listOfMixedTypes.add(listOfStrings);
        listOfMixedTypes.add(matches);
		return listOfMixedTypes;
	}

}
