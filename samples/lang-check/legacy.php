<?php
// Legacy admin script (benchmark fixture).
$conn = mysqli_connect("localhost", "app", getenv("DB_PASS"), "shop");

$rows = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
echo "Hello " . $_GET['name'];
system("convert " . $_POST['file'] . " out.png");
$prefs = unserialize($_COOKIE['prefs']);
include($_GET['page']);
$hash = md5($_POST['password']);

$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
echo htmlspecialchars("static text");
