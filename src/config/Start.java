package config;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

public class Start extends Application
	{
		public static Stage primaryStage;
		
		public static void main(String[] args)
		{
			Application.launch(args);
		}
			
		@Override
	//main entry point to the application
		public void start(Stage primaryStage) throws Exception
		{
	//create the main window
			Start.primaryStage = primaryStage;
			Start.primaryStage.setTitle("Data protection tool");
			Start.primaryStage.setWidth(625);
			Start.primaryStage.setHeight(435);
			
			  
			    
	//load fxml file from location		
			FXMLLoader loader = new FXMLLoader();
			loader.setLocation(Start.class.getResource("../view/MainView.fxml"));
			
	//scene is the container for all content in a scene graph		
			AnchorPane layout = loader.load();
			Scene mainViewScene = new Scene(layout);
			Start.primaryStage.setResizable(false);
			Start.primaryStage.setScene(mainViewScene);
			Start.primaryStage.show();
			
			
			
			
			
		}
		
		
	}