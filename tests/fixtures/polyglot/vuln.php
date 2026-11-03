<?php
$user = $_GET['user'];
$res = mysql_query("SELECT * FROM users WHERE name = '" . $user . "'");
$data = unserialize($_POST['blob']);
eval($_GET['expr']);
system("ping " . $_GET['host']);
