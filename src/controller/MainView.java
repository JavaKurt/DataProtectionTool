package controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import java.io.PrintWriter;
import java.net.URL;
import java.nio.file.Files;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import java.security.spec.InvalidKeySpecException;
import java.util.ResourceBundle;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;

import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;

import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;

import javafx.stage.Stage;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;


public class MainView implements Initializable{
	@FXML	private AnchorPane anchorpane;
	@FXML 	private Button uploadBtn;
	@FXML 	private Button encryptBtn;
	@FXML   private Button decryptBtn;
	
	@FXML private Button clear;
	
	@FXML 	private ComboBox<String> comboBox;
	@FXML	private TextField filePathTF;
	@FXML	private TextArea textBox1; //total file path print
	@FXML 	private TextArea textBox2; //file dir path print	
	@FXML 	private PasswordField passwordField;
	

	private static String password = null;
	private static String x;
	private static String filepath = null;
	private static String newLine = "\n";
	private static String directorypath;	
	private static Cipher ecipher;
	private static Cipher dcipher;
	
	private static byte[] content;
	private static byte[] encrypted;
	private static byte[] decrypted;
	private static byte[] salt;
	
	private static Key decryptKey;


	public MainView() {
		
	}
	//set values for combo box
	ObservableList<String > list = FXCollections.observableArrayList(
			"Text File", "Image File", "Folder"
			);
	
	@Override
	public void initialize(URL arg0, ResourceBundle arg1)
	{	
		//initialise combo box
		comboBox.setItems(list);
		//initialise upload button
		uploadBtn.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent e)
			{
		//select type of file		
				if (comboBox.getValue() == "Text File") {		
					chooseTextFile();	
				}
				else if (comboBox.getValue() == "Image File") {					
					chooseImageFile();
				}
				else if (comboBox.getValue() == "Folder") {					
					chooseFolder();
				}			
			}
		});
		//initialise encryption button
		encryptBtn.setOnAction(new EventHandler<ActionEvent>()
			{
			@Override
			public void handle(ActionEvent e) {				
				//get password from password text field
				getPassword();
				
				if(filepath.endsWith(".txt") && password.isEmpty()) {			
					//encrypt text file
					textBox1.setText("Text file encrypted: " + newLine + filepath);				
					encryptTextFile();
				}
				
				else if(filepath.endsWith(".txt") && password != null) {		
					//encrypt text file using a password
					textBox1.setText("Password: " + password + newLine + "Has been used to encrypt: " + newLine + filepath);
					try {
						encryptTextWithPassword();
					} catch (Exception e1) {
						e1.printStackTrace();
					}
				}

				else if(filepath.endsWith(".jpg") || (filepath.endsWith(".png") || (filepath.endsWith(".pdf"))) && password.isEmpty()) { 
					//encrypt an image file
					textBox1.setText("Image file encrypted: " + newLine + filepath);
					encryptImageFile();
			
				}
				else if(filepath.endsWith(".jpg") || (filepath.endsWith(".png") || (filepath.endsWith(".pdf"))) && password != null) { 	
					//encrypt image file using a password
					textBox1.setText("Password: " + password + newLine + "Has been used to encrypt: " + newLine + filepath);
					try {
						encryptImageWithPassword();
					} catch (Exception e1) {
						e1.printStackTrace();
					}
					
				}
				else if(filepath == directorypath && password.isEmpty()) {
					//encrypt a folder
					textBox1.setText("Folder encrypted: " + newLine + filepath);
					encryptFolder();				
				}
				else if(filepath == directorypath && password != null) {
					//encrypt a folder with a password
					textBox1.setText("Password: " + password + newLine + "Has been used to encrypt: " + newLine + filepath);				
					encryptFolderWithPassword();
				}			
			}
		});	
	
	 decryptBtn.setOnAction(new EventHandler<ActionEvent>() {
		 public void handle(ActionEvent e) {
			
		//get password for decryption 
			 getPassword();
			 
		 if(filepath.endsWith(".txt") && password.isEmpty()) {
			 //decrypt text file
			 textBox2.setText("Text file decrypted :" + newLine + filepath);
			 decryptTextFile();	
			}
		 
		 else if(filepath.endsWith(".txt") && password != null) {
			 //decrypt text file with password
			 textBox2.setText("Password: " + password + newLine + "Has been used to decrypt: " + newLine + filepath);
			 try {
				decryptTextWithPassword();
			} catch (Exception e1) {
				e1.printStackTrace();
			}
		 }
		 
		 else if(filepath.endsWith(".jpg") || (filepath.endsWith(".png") || (filepath.endsWith(".pdf"))) && password.isEmpty()) { 
			 //decrypt image file 
			 textBox2.setText("Image file decrypted :" + newLine + filepath);
			 decryptImageFile();
			 
			}
		 else if(filepath.endsWith(".jpg") || (filepath.endsWith(".png") || (filepath.endsWith(".pdf"))) && password != null) { 
			 //decrypt image file with password
			 textBox2.setText("Password: " + password + newLine + "Has been used to decrypt: " + newLine + filepath);
			 try {
				decryptImageWithPassword();
			} catch (Exception e1) {
				e1.printStackTrace();
			}
		 }
		 else if(filepath == directorypath && password.isEmpty()) {
			 //decrypt folder
			 textBox2.setText("Folder decrypted :" + newLine + filepath);
			decryptFolder();
				
			}
		 else if(filepath == directorypath && password != null){
			//decrypt folder with password
			textBox2.setText("Password: " + password + newLine + "Has been used to decrypt: " + newLine + filepath);
			try {
				decryptFolderWithPassword();
			} catch (IllegalBlockSizeException | BadPaddingException e1) {
				e1.printStackTrace();
			} catch (InvalidKeyException e1) {
				e1.printStackTrace();
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (InvalidAlgorithmParameterException e1) {
				e1.printStackTrace();
			} catch (InvalidKeySpecException e1) {
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				e1.printStackTrace();
			}
		 }
		 }
	});			
	}
	
	private static byte[] getFile() {
		//specifies file location
		File f = new File(filepath);
		InputStream is = null;
		try {
			is = new FileInputStream(f);
		}	catch (FileNotFoundException e2) {
			e2.printStackTrace();
		}
		//reads the bytes of a file
		byte[] content = null;
		try {
			content = new byte[is.available()];
		}	catch (IOException e1) {
			e1.printStackTrace();
		}
		try {
			is.read(content);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return content;
	}
			
	private void chooseTextFile(){
		//creates instance of FileChooser and sets a file extension specifically for text files
		FileChooser filechooser = new FileChooser();
		FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("TEXT FILES(*.txt)", "*.txt");
		filechooser.getExtensionFilters().add(extFilter);

		//sets title of the filechooser window
		filechooser.setTitle("Open File Dialog - SELECT TEXT FILE" );
		Stage primaryStage = (Stage)anchorpane.getScene().getWindow();

		//if the file exists, this will set the file path text both to the file path of the chosen file
		File file = filechooser.showOpenDialog(primaryStage);
		if(file != null)
		{
			filePathTF.setText(file.getPath());
			filepath = file.getPath();
		}
	}
	
	private void chooseImageFile() {
		//creates instance of FileChooser and sets a file extension specifically for image files
		FileChooser filechooser = new FileChooser();
		filechooser.getExtensionFilters().addAll(
				new FileChooser.ExtensionFilter("JPG", "*.jpg"),
				new FileChooser.ExtensionFilter("PNG", "*.png"),
				new FileChooser.ExtensionFilter("PDF", "*.pdf")
				);
		
		//sets title of the filechooser window
		filechooser.setTitle("Open File Dialog - select image file");
		Stage primaryStage = (Stage)anchorpane.getScene().getWindow();
		
		//if the file exists, this will set the file path text both to the file path of the chosen file
		File file = filechooser.showOpenDialog(primaryStage);
		if(file != null)
		{
			filePathTF.setText(file.getPath());
			filepath = file.getPath();
		}
				
	}
	
	private void chooseFolder() {
		//creates instance of DirectoryChooser and allows the user to only select a directory
		DirectoryChooser directorychooser = new DirectoryChooser();
		
		//sets title of the filechooser window
		directorychooser.setTitle("Folder");
		Stage primaryStage = (Stage)anchorpane.getScene().getWindow();
		
		//if the directory exists, this will set the file path text both to the file path of the chosen file
		File directory = directorychooser.showDialog(primaryStage);
		if (directory != null)
		{
			filePathTF.setText(directory.getPath());
			filepath = directory.getPath();
			directorypath = directory.getPath();
		}	
	}
		
	private static Key getAESKey() throws NoSuchAlgorithmException {
		//generates key for AES
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);
		Key key = keyGenerator.generateKey();

		return key;
	}
	
	private void getPassword() {
		//gets password from user input, from the password text field
		password = passwordField.getText();

	}	
	
	private static void encryptTextFile() {
		try {
			//gets key and a files byte contents
			decryptKey = getAESKey();			
			byte[] content = getFile();

			//method to encrypt text file
			encrypted = encryptWithAES(decryptKey, content);		
			
			//creates a writer to write to designated file			
			PrintWriter writer = new PrintWriter(filepath);
			
			//decodes the bytes into a string and places it inside file
			x = new Base64().encodeToString(encrypted);
			writer.println(x);
			writer.close();		
			
		} catch(NoSuchAlgorithmException e1){
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}

	private static void decryptTextFile() {
		try {			
			//creates a writer to write to designated file
			PrintWriter writer = new PrintWriter(filepath);
			
			//method to decrypt file - bytes are decoded from byte to string in this method
			decrypted = decryptFileWithAES(decryptKey, encrypted);	
			
			//prints the decrypted text into chosen file
			writer.println(new String(decrypted));
			writer.close();		
			
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	private static void encryptImageFile() {
		try {
			//get key and files contents in bytes
			decryptKey = getAESKey();
			byte[] content = getFile();		
		
			//method to encrypt image file
			encrypted = encryptIFMethod(decryptKey, content);			
			
			//method to over-write image file with encrypted version
			saveImageFile(encrypted);		
		} catch (NoSuchAlgorithmException e1) {					
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	private static void decryptImageFile() {
		try {
			//get files contents in bytes
		//	byte[] content = getFile();						
			
			//method to decrypt image file
			decrypted = decryptIFMethod(decryptKey, encrypted);
			
			//method to overwrite encrypted image file with decrypted image file
			 saveImageFile(decrypted);						
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	private static void encryptFolder() {
		try {
			//get instance of a new file from the users chosen file
			File f = new File(filepath);	
			
			//method to encrypt the contents a folder
			encryptFolderMethod(f);	
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
	}
	
	private static void decryptFolder() {
		try {
			//get instance of a new file from the users chosen file
			File f = new File(filepath);
			
			//method to decrypt the contents of a folder
			decryptFolderMethod(f);
		} catch(IOException e1) {
			e1.printStackTrace();
		} catch(NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
	}
	
	private static void encryptTextWithPassword() throws Exception {	
		//get files contents in bytes and create new fileoutputstream using the users selected file path
		byte[] content = getFile();		
		FileOutputStream outFile = new FileOutputStream(filepath);
	
		//create key and allocate password to char array
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

		//create salt
		byte[] salt = new byte[8];
		Random random = new Random();
		random.nextBytes(salt);

		//create pbeparamspec using salt 
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
		
		//encryption 
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
		outFile.write(salt);

		try {
			encrypted = cipher.doFinal(content);
			outFile.write(encrypted);
			x = new Base64().encodeToString(encrypted);
		} catch(Exception e) {
			e.printStackTrace();
		}
		//flush and close outputstreams
		outFile.flush();
		outFile.close();		
	}
	
	public static void decryptTextWithPassword() throws Exception {	
		//get keys and allocate password to char array
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

		//create file input stream to read the users file
		FileInputStream fis = new FileInputStream(filepath);
		
		//initialise salt and read salt from text file
		byte[] salt = new byte[8];
		fis.read(salt);

		//create pbeparamspec using generated salt
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);

		//decryption
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
		FileOutputStream fos = new FileOutputStream(filepath);
	
		try {
			decrypted = cipher.doFinal(encrypted);
			fos.write(decrypted);
		} catch(Exception e) {
			e.printStackTrace();
		}
		fis.close();
		fos.flush();
		fos.close();	
	}
	
	public static void encryptImageWithPassword() throws Exception{
		//get files contents in bytes and create new fileoutputstream using the users selected file path
		byte[] content = getFile();		
		FileOutputStream outFile = new FileOutputStream(filepath);
	
		//create key and allocate password to char array
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

		//initialise and get a random salt
		byte[] salt = new byte[8];
		Random random = new Random();
		random.nextBytes(salt);

		//create new pbeparamspec with salt
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
		
		//encrypt image file with a password
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
		outFile.write(salt);
		try {
			encrypted = cipher.doFinal(content);
			outFile.write(encrypted);
		} catch(Exception e) {
			e.printStackTrace();
		}
		outFile.flush();
		outFile.close();
	}
	 
	public static void decryptImageWithPassword() throws Exception{
		//create key and allocate password to char array
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

		//create file input stream to read the users file
		FileInputStream fis = new FileInputStream(filepath);
		
		//initialise salt and read salt from text file
		byte[] salt = new byte[8];
		fis.read(salt);

		//create pbeparamspec using generated salt
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);

		//encrypt image file
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
		FileOutputStream fos = new FileOutputStream(filepath);
	
		try {
			decrypted = cipher.doFinal(encrypted);
			fos.write(decrypted);
		} catch(Exception e) {
			e.printStackTrace();
		}
		fis.close();
		fos.flush();
		fos.close();
	} 
	
	private static byte[] encryptWithAES(Key key, byte[] fileInput){
		
		byte[] encrypted = null;
		try {
			//initiate a Cipher variable
			ecipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			//encryption
			ecipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted = ecipher.doFinal(fileInput);
			//convert encrypted bytes to readable string						
			x = new Base64().encodeToString(encrypted);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encrypted;
	}
	
	private static byte[] decryptFileWithAES(Key key, byte[] decrypto) {
		decrypted = null;
		try {
			//initiate a Cipher variable
			dcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			//decryption
			dcipher.init(Cipher.DECRYPT_MODE, key);
			//convert encrypted bytes to readable string
			encrypted = new Base64().decode(x);	
			decrypted = dcipher.doFinal(encrypted);			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decrypted;
	}
	
	private static byte[] decryptFolderWithAES(Key key, byte[] encrypted) {
		decrypted = null;
		try {
			//initiate a Cipher variable
			dcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			//decryption
			dcipher.init(Cipher.DECRYPT_MODE, key);
			
			encrypted = new Base64().decode(content);			
			decrypted = dcipher.doFinal(encrypted);
			
			} catch (Exception e) {
				e.printStackTrace();
			}
		return decrypted;
		
	}

	private static byte[] encryptIFMethod(Key key, byte[] inputFile) {
		byte[] encrypted = null;
		try {
			//encryption
			ecipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			ecipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted = ecipher.doFinal(inputFile);
		} catch(Exception e) {
			e.printStackTrace();
		}
		return encrypted;
	}
	
	private static byte[] decryptIFMethod(Key key, byte[] encrypted) {
		byte[] decrypted = null;
		try {
			//decryption
			dcipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			dcipher.init(Cipher.DECRYPT_MODE, key);
			decrypted = dcipher.doFinal(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decrypted;
	}
	
	private static Collection <File> encryptFolderMethod(File dir) throws IOException, NoSuchAlgorithmException {		
		//get key
		decryptKey = getAESKey();		
		//set hashset
		final Set<File> fileTree = new HashSet<File>();		
		//method for traversing through a directory and encrypting all files
		for(File entry: dir.listFiles()) {
			if(entry.isFile()) {				
				fileTree.add(entry);							
					//get the bytes of the file
					byte[] content = Files.readAllBytes(entry.toPath());				
					//if the file is a text file use this method to encrypt
					if(entry.getPath().endsWith(".txt")) {
						encrypted = encryptWithAES(decryptKey, content);
						PrintWriter writer = new PrintWriter(entry);
						x = new Base64().encodeToString(encrypted);						
						writer.println(x);
						writer.close();
					}
					//if the file is an image file use this method to encrypt
					else if(entry.getPath().endsWith(".png")|| (entry.getPath().endsWith(".jpg"))|| (entry.getPath().endsWith(".pdf"))) {
						encrypted = encryptIFMethod(decryptKey, content);						
						FileOutputStream fos  = new FileOutputStream(entry);
						fos.write(encrypted);
						fos.close();	
					}
					else {
						System.out.println("Unfortunately the program can't encrypt that file extension yet. Maybe in the next patch.");
					}
			}
			else {
				fileTree.addAll(encryptFolderMethod(entry));
			}
		}
		return fileTree;
	}
	
	private static Collection<File> decryptFolderMethod(File dir) throws IOException, NoSuchAlgorithmException {
		
		//if a directory is empty returns empty list
		if (null == dir || !dir.isDirectory()) {
    		return Collections.emptyList();
    	}
		//set hash set
    	final Set<File> fileTree = new HashSet<File>(); 
    	
    	//method for traversing through a directory and decrypting all files
    		for (File entry: dir.listFiles())
    		{
    			if(entry.isFile()) {
    				fileTree.add(entry);

    				
    				//if file is a text file, decrypts using this method
    				if(entry.getPath().endsWith(".txt")) {
    					content = Files.readAllBytes(entry.toPath());
    					decrypted = decryptFolderWithAES(decryptKey, content);
    					
    					PrintWriter writer = new PrintWriter(entry);
    					
    					writer.println(new String (decrypted));
    					writer.close();
    				}
    				//if the file is an image file, decrypts using this method
    				else if (entry.getPath().endsWith(".png")|| (entry.getPath().endsWith(".jpg"))|| (entry.getPath().endsWith(".pdf"))) {
    					encrypted = Files.readAllBytes(entry.toPath());
    					decrypted = decryptIFMethod(decryptKey, encrypted);
    				
    					FileOutputStream fos  = new FileOutputStream(entry);
						fos.write(decrypted);
						fos.close();
    				}
    			}
    			else {
    				fileTree.addAll(decryptFolderMethod(entry));
    			}
    		}
    		return fileTree;
	}
		
	private static void saveImageFile(byte[] bytes) throws IOException{
		//opens output stream to write over the existing file  with either the encrypted version or decrypted version
		FileOutputStream fos  = new FileOutputStream(filepath);
		fos.write(bytes);
		fos.close();
	}
	
	private static void encryptFolderWithPassword(){
		//creates new instance of users selected file
		File f = new File(filepath);
		try {
			//method for encrypting folder with password
			folderPassMethod(f);
		} catch (Exception e) {
			e.printStackTrace();
		}
}

	public static Collection<File> folderPassMethod(File dir) throws Exception, FileNotFoundException, IllegalBlockSizeException, BadPaddingException 
	{ 
	//creates hash set
		final Set<File> fileTree = new HashSet<File>();
		
		//creates key and allocates password to char array
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
	
		//generates new random salt
		salt = new byte[8];
		Random random = new Random();
		random.nextBytes(salt);
	
		//creates pbeparamspec with generated salt
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
		
		//method to encrypt the contents of a folder
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
		
		for(File entry: dir.listFiles()) {
			if(entry.isFile()) {
				
				fileTree.add(entry);
					
					//if the for loop finds a text file, this method will run and encrypt the text file
					if(entry.getPath().endsWith(".txt")) {
				
						try {
						//read all bytes of the current file
						content = Files.readAllBytes(entry.toPath());
						
						//create new instance of printwriter to write to the current file
						PrintWriter writer = new PrintWriter(entry);
						//print the salt to the current file
						writer.println(salt);
						
						//encrypt the file and convert bytes to readable string
						encrypted = cipher.doFinal(content);
						x = new Base64().encodeToString(encrypted);
						
						//print readable string to chosen file
						writer.println(x);										
						writer.close();
						
					} catch(Exception e) {
						e.printStackTrace();
					}
				
				}		
				//if the for loop traverses through and finds an image file, this method will encrypt image files
				else if(entry.getPath().endsWith(".png")|| (entry.getPath().endsWith(".jpg"))|| (entry.getPath().endsWith(".pdf"))) {
					
					//create file output stream for current file
					FileOutputStream fos  = new FileOutputStream(entry);
					try {
						//encrypt image file
						encrypted = cipher.doFinal(content);
						fos.write(encrypted);
					} catch(Exception e) {
						e.printStackTrace();
					}
					fos.flush();
					fos.close();
				}
				else {
					System.out.println("Unfortunately the program can't encrypt that file extension yet. Maybe in the next patch.");
				}
		}
		else {
			fileTree.addAll(encryptFolderMethod(entry));
		}
	}
	return fileTree;
}

	private static void decryptFolderWithPassword() throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException {
		try {
			//create new instance of file from users chosen file
			File f = new File(filepath);
			
			//decrypt folder with a password method
			decryptFolderWithPass(f);
		} catch(IOException e1) {
			e1.printStackTrace();
		}
}

	public static Collection<File> decryptFolderWithPass(File dir) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException, NoSuchPaddingException{
	
		//create key and allocate password to char array
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
	
		//create pbeparamspec with generated salt
		PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
		
		//decryption method for a folder using a password
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
		
		
		final Set<File> fileTree = new HashSet<File>(); 
		
		//method will traverse through a directory and decrypt all files
			for (File entry: dir.listFiles())
			{
				if(entry.isFile()) {
					fileTree.add(entry);
					
					//if the file is a text file, this method will decrypt all text files
					if(entry.getPath().endsWith(".txt")) {		
						
					//gets the bytes of the current file
					content = Files.readAllBytes(entry.toPath());	
						try {
							
							//creates instance of file inputstream of current file
							FileInputStream fis = new FileInputStream(entry);
		
							//creates instance of printwriter for current file
							PrintWriter writer = new PrintWriter(entry);
							
							//checks the salt of the current file
							fis.read(salt);	
							
							//decrypts and converts the encrypted bytes into readable string 
							encrypted = new Base64().decode(x);							
							decrypted = cipher.doFinal(encrypted);

							//prints the decrypted text to the current file
	    					writer.println(new String (decrypted));
	    					writer.close();	
							
	    					//closes input stream
	    					fis.close();												
						} catch(Exception e) {
							e.printStackTrace();
						}				
				}
				//this method will run if the file is an image file
				else if (entry.getPath().endsWith(".png")|| (entry.getPath().endsWith(".jpg"))|| (entry.getPath().endsWith(".pdf"))) {
					FileOutputStream fos  = new FileOutputStream(entry);
					try {
						//method for decrypting image file
						decrypted = cipher.doFinal(encrypted);
						fos.write(decrypted);
					} catch(Exception e) {
						e.printStackTrace();
					}
					//closes output streams
					fos.flush();
					fos.close();
				}
			}
			else {
				fileTree.addAll(decryptFolderMethod(entry));
			}
		}
		return fileTree;
}
}
	


