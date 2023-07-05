
<!DOCTYPE html>


<head>
	<title>Home</title>
	 <link rel="stylesheet" type="text/css" href="../static/css/styles.css"> 
	<link rel="stylesheet" type="text/css" href="{{ url_for('static', filename='css/styles.css') }}">
    
   
</head>


 <body >
 
   

	<header>
		<div class="container">
		<div id="brandname">
			DETECTOR FOR PHISHING WEBSITES
		</div>
		<br> <br><h3>Phishing is a fraudulent technique that is used  over the Internet to deceive users with the goal  of extracting their personal information such as  username, passwords, credit card, and bank  account information. The key to phishing is  deception.  Phishing was discovered in 1996, and  today, it is one of the most severe cybercrimes  faced by the Internet users.There are number of users who purchase products online and make payment through various websites.There are multiple websites who ask user to provide sensitive data such as username, password or credit card details etc. often for malicious reasons. This type of websites is known as phishing website.  
 </h3>
		
	</div>
	</header>
    
	<div class="ml-container">

		 <form  method="POST" action="dbdata.php" >
		      
		     <br> <br><div align="center"><font size="6" color="blue" face="verdana" >Enter your URL here and know if it is a Good URL or a Bad URL! </font></div>
		     <label for="url">
		      <br> <br><div align="center" ><input type="text" id="url" name="url" class="formis" required="required" placeholder="Enter URL" size="100"  > </input></div>
		       <br/>
		      </label>
        
		     <br><div align="center"><input type="submit" class="btn-info" name="submit" value="PREDICT" id="PREDICT   " ></div>
		
		    </form>

		
	</div>

	
	


</body>
</html>

 
 
 
 
 
 