package burp;

import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import org.json.*;


public class BurpExtender implements IBurpExtender,IScannerCheck,ITab {
	private PrintWriter mStdErr;
	private PrintWriter mStdOut;
	private JPanel jpanel;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private List<Issue> passiveIssues;
	private List<Issue> activeIssues;
	private List<Issue> allIssues;
	private DbUtils dbRunner;
	private StringUtils strUtil;


	public static void main(String[] args) {
		/*
		 * Running burp suite from eclipse ide
		 */
		//burp.StartBurp.main(args);

	}


	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		this.callbacks.setExtensionName("Sensitive Data Analyzer");
		this.mStdErr = new PrintWriter(callbacks.getStderr(), true);
		this.mStdOut = new PrintWriter(callbacks.getStdout(), true);
		this.callbacks.registerScannerCheck(this);
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			mStdErr.println("forName: " + e.getMessage());
		}
		this.jpanel = new JPanel();
		this.passiveIssues = new ArrayList<Issue>();
		this.activeIssues = new ArrayList<Issue>();
		this.allIssues = new ArrayList<Issue>();
		this.dbRunner = new DbUtils();
		this.strUtil  = new StringUtils();
		//uiutil = new UIUtiles(callbacks,mStdErr);
		SwingUtilities.invokeLater(new Runnable() {

			@Override
			public void run() {
				// TODO Auto-generated method stub

				// Test button
				JButton test = new JButton("Test");
				test.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub

					}
				});

				// Test2 button
				JButton test2 = new JButton("Test2");
				test2.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
					}
				});


				// Create all section directly
				JButton createAutomatic = new JButton(strUtil.btnCreateAuto);
				createAutomatic.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						try {
							dbRunner.generateDB();
							createIssues(strUtil.userDir+strUtil.fileName, mStdErr);
							generateIssuesList();
							JOptionPane.showMessageDialog(null, strUtil.createAutoInfo, strUtil.createAutoHeader, JOptionPane.INFORMATION_MESSAGE);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							JOptionPane.showMessageDialog(null, strUtil.generalError + e1.getMessage(), strUtil.createAutoHeader, JOptionPane.ERROR_MESSAGE);
						}
					}
				});

				// Create DB if it is not created
				JButton createDB = new JButton(strUtil.btnCreateDB);
				createDB.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						try {
							dbRunner.generateDB();
							JOptionPane.showMessageDialog(null, strUtil.createDBInfo, strUtil.createDBHeader, JOptionPane.INFORMATION_MESSAGE);

						} catch (Exception e1) {
							// TODO Auto-generated catch block
							JOptionPane.showMessageDialog(null, strUtil.generalError + e1.getMessage(), strUtil.createDBHeader, JOptionPane.ERROR_MESSAGE);
						}
					}
				});

				// Load file on the specific path.
				JButton loadIssueList = new JButton(strUtil.btnLoadIssue);
				loadIssueList.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						try {
							createIssues(strUtil.userDir+strUtil.fileName, mStdErr);
							JOptionPane.showMessageDialog(null, strUtil.loadIssueInfo, strUtil.loadIssueHeader, JOptionPane.INFORMATION_MESSAGE);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							JOptionPane.showMessageDialog(null, strUtil.generalError + e1.getMessage(), strUtil.loadIssueHeader, JOptionPane.ERROR_MESSAGE);
						}
					}
				});

				// Load file form signified path.
				JButton selectFile = new JButton(strUtil.btnSelectFile);

				selectFile.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						JFileChooser customStoreFileNameFileChooser = new JFileChooser();
						customStoreFileNameFileChooser.setDialogTitle("Select the Issues file to use...");
						customStoreFileNameFileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
						customStoreFileNameFileChooser.setDialogType(JFileChooser.SAVE_DIALOG);
						customStoreFileNameFileChooser.setDragEnabled(false);
						customStoreFileNameFileChooser.setMultiSelectionEnabled(false);
						customStoreFileNameFileChooser.setAcceptAllFileFilterUsed(false);
						customStoreFileNameFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
						customStoreFileNameFileChooser.setFileHidingEnabled(true);
						int dbFileSelectionReply = customStoreFileNameFileChooser.showDialog(jpanel, "Use");
						System.out.println(dbFileSelectionReply);

						if (dbFileSelectionReply == 0) {
							String customStoreFileName = customStoreFileNameFileChooser.getSelectedFile().getAbsolutePath().replaceAll("\\\\", "/");
							try {
								createIssues(customStoreFileName,mStdErr);
								JOptionPane.showMessageDialog(null, strUtil.selectFileInfo + customStoreFileName, strUtil.selectFileHeader, JOptionPane.INFORMATION_MESSAGE);
							} catch (Exception e1) {
								// TODO Auto-generated catch block
								JOptionPane.showMessageDialog(null, strUtil.generalError + e1.getMessage(), strUtil.selectFileHeader, JOptionPane.ERROR_MESSAGE);
							}
						}
					}
				});

				// Generate Issue's List.
				JButton generateIssue = new JButton(strUtil.btnGenerateIssue);
				generateIssue.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						try {
							generateIssuesList();
							JOptionPane.showMessageDialog(null, strUtil.generateIssueInfo, strUtil.generateIssueHeader, JOptionPane.INFORMATION_MESSAGE);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							JOptionPane.showMessageDialog(null, strUtil.generalError + e1.getMessage(), strUtil.generateIssueHeader, JOptionPane.ERROR_MESSAGE);
						}
					}
				});
				//Clear Issue from DB
				JButton clearIssues = new JButton(strUtil.btnRemoveIssues);
				clearIssues.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						try {
							dbRunner.removeIssuteTable();
							JOptionPane.showMessageDialog(null, strUtil.removeIssueInfo, strUtil.removeIssueHeader, JOptionPane.INFORMATION_MESSAGE);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							JOptionPane.showMessageDialog(null, strUtil.generalError + e1.getMessage(), strUtil.removeIssueHeader, JOptionPane.ERROR_MESSAGE);
						}
					}
				});
				//Clear Issue from DB
				JButton showIssues = new JButton(strUtil.btnShowIssues);
				showIssues.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						try {
							List<String[]> activeIssuesDB = dbRunner.getIssues("Active");
							List<String[]> passiveIssuesDB = dbRunner.getIssues("Passive");
							String issuesInfo = String.format(strUtil.showIssueInfo,passiveIssuesDB.size(),activeIssuesDB.size(),passiveIssues.size(),activeIssues.size());
							JOptionPane.showMessageDialog(null, issuesInfo, strUtil.showIssueHeader, JOptionPane.INFORMATION_MESSAGE);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							JOptionPane.showMessageDialog(null, strUtil.generalError + e1.getMessage(), strUtil.showIssueHeader, JOptionPane.ERROR_MESSAGE);
						}
					}
				});
				JPanel gridPanel = new JPanel(new GridLayout(7, 0, 10, 10));
				gridPanel.add(createAutomatic);
				gridPanel.add(createDB);
				gridPanel.add(loadIssueList);
				gridPanel.add(selectFile);
				gridPanel.add(generateIssue);
				gridPanel.add(clearIssues);
				gridPanel.add(showIssues);
				jpanel.setLayout(new FlowLayout(FlowLayout.CENTER, 10, 5));
				jpanel.add(gridPanel);	
				callbacks.customizeUiComponent(getUiComponent());
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}


	public void createIssues(String fileName, PrintWriter mStdErr) throws FileNotFoundException, JSONException, SQLException {
		InputStream inputstream = new FileInputStream(fileName);
		JSONTokener tokener = new JSONTokener(inputstream);
		JSONObject issueList = new JSONObject(tokener);
		String insertValue;
		String insertName;
		String variable;
		JSONArray issueArray = issueList.getJSONArray("data");
		for (int i = 0; i < issueArray.length(); i++) {
			insertValue = "";
			variable = "";
			for (int j = 0; j < strUtil.jsonVariables.length; j++) {
				if(j == 2 || j ==1) {
					variable = Base64.getEncoder().encodeToString(issueArray.getJSONObject(i).getString(strUtil.jsonVariables[j]).getBytes());
				} else {
					variable = issueArray.getJSONObject(i).getString(strUtil.jsonVariables[j]);
				}
				insertValue += "\"" + variable;
				if (strUtil.jsonVariables.length-1 == j) {
					insertValue += "\"";
				} else {
					insertValue += "\",";
				}
			}
			insertName = issueArray.getJSONObject(i).getString("Name");
			dbRunner.insertValue(strUtil.addIssue.replace("_replace_",insertValue),insertName,mStdErr);
		}
	}


	public void generateIssuesList() throws SQLException{
		this.passiveIssues.clear();
		this.activeIssues.clear();
		this.allIssues.clear();
		List<String[]> passiveArray = dbRunner.getIssues("Passive");;
		List<String[]> activeArray = dbRunner.getIssues("Active");

		for (int i = 0; i < passiveArray.size(); i++) {
			this.passiveIssues.add(new Issue(passiveArray.get(i)[1],passiveArray.get(i)[2],passiveArray.get(i)[3],passiveArray.get(i)[4],passiveArray.get(i)[5],passiveArray.get(i)[6]));
			this.allIssues.add(new Issue(passiveArray.get(i)[1],passiveArray.get(i)[2],passiveArray.get(i)[3],passiveArray.get(i)[4],passiveArray.get(i)[5],passiveArray.get(i)[6]));
		}
		for (int i = 0; i < activeArray.size(); i++) {
			this.activeIssues.add(new Issue(activeArray.get(i)[1],activeArray.get(i)[2],activeArray.get(i)[3],activeArray.get(i)[4],activeArray.get(i)[5],activeArray.get(i)[6]));
			this.allIssues.add(new Issue(activeArray.get(i)[1],activeArray.get(i)[2],activeArray.get(i)[3],activeArray.get(i)[4],activeArray.get(i)[5],activeArray.get(i)[6]));
		}
	}


	public List<IScanIssue> findIssues(IHttpRequestResponse baseRequestResponse, List<Issue> issueList){
		List<IScanIssue> issues = new ArrayList<>();
		for (int i = 0; i < issueList.size(); i++) {
			List<List> listOfMixedTypes = strUtil.checkMatches(new String(baseRequestResponse.getResponse()),(new String(Base64.getDecoder().decode(issueList.get(i).getRegex())).split("_split_")));
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
				String desc = strUtil.createDescriptionIssue(matchArray,issueList.get(i).getDescription()); 
				issues.add(new CustomScanIssue(baseRequestResponse.getHttpService(), this.helpers.analyzeRequest(baseRequestResponse).getUrl(), new IHttpRequestResponse[]{this.callbacks.applyMarkers(baseRequestResponse, (List) null, matches)}, "Sensitive Data Analyser - "+issueList.get(i).getName(), desc , severity,issueList.get(i).getCofidence()));
			}
		}
		return issues;
	}


	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		// TODO Auto-generated method stub
		if (!this.callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
			return null;
		}
		if (this.passiveIssues.size() == 0) {
			mStdErr.println(strUtil.errorEmptyIssueList);
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
		if (!this.callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl())) {
			return null;
		}
		if (this.activeIssues.size() == 0) {
			mStdErr.println(strUtil.errorEmptyIssueList);
			return null;
		} else {
			List<IScanIssue> issues = new ArrayList<>();
			String[] payloads;
			String payload;
			for (int i = 0; i < activeIssues.size(); i++) {
				payloads = (new String(Base64.getDecoder().decode(activeIssues.get(i).getPayload()))).split("_split_");
				for (int j = 0; j < payloads.length; j++) {
					payload = payloads[j];
					byte[] checkRequest = insertionPoint.buildRequest(java.net.URLDecoder.decode(payload).getBytes());
					IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
							baseRequestResponse.getHttpService(), checkRequest);
					issues.addAll(findIssues(checkRequestResponse,allIssues));
				}
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


	@Override
	public String getTabCaption() {
		// TODO Auto-generated method stub
		return "Sensitive Data Analyzer";
	}


	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return this.jpanel;
	}
}

