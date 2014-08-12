<?php


$q = array('email', 'last_name', 'first_name', 'time_zone');

$sql = "select ".implode(',', $q)." from t_users where id=:user_id";

$p = 'db.proficiency.';

GLOBAL $_CONFIG;

$db = $_CONFIG[$p.'name'];
$host = $_CONFIG[$p.'host'];
$port = $_CONFIG[$p.'port'];
$user = $_CONFIG[$p.'user'];
$pass = $_CONFIG[$p.'password'];

$dsn = "mysql:dbname=$db;host=$host";
$pdo = new PDO($dsn, $user, $pass);
$st = $pdo->prepare($sql);
$st->execute(array(':user_id' => $this->data['user_id']));
$data = $st->fetchAll();

if (count($data) < 1) {
    die(json_encode(array()));
}
$data = $data[0];
$newData = array();

foreach ($q as $k) {
    $newData[$k] = $data[$k];
}

echo (json_encode($newData));

?>
