<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "data5";
global $url;
if(isset($_POST['submit']))
 {$url=$_POST['url'];
   //echo $url;
 }

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);
// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} 

$sql = ("INSERT INTO url(url) VALUES ('$url')") ;
if ($conn->query($sql) === TRUE) {
$command = escapeshellcmd('python phish.py');
$output = shell_exec($command);
echo $output;
}
else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}
$conn->close();

?>