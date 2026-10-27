<?php
// Legacy admin script (benchmark fixture).
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "shop");

$rows = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);  // VULN:sqli
echo "Hello " . $_GET['name'];  // VULN:xss
system("convert " . $_POST['file'] . " out.png");  // VULN:cmdi
$prefs = unserialize($_COOKIE['prefs']);  // VULN:deserialization
include($_GET['page']);  // VULN:path_traversal
$hash = md5($_POST['password']);  // VULN:weak_crypto

$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
echo htmlspecialchars("static text");
