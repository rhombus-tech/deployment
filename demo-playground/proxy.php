<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: *');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit();
}

$url = 'https://zk-evm.org/status';

$context = stream_context_create([
    'http' => [
        'method' => 'GET',
        'header' => "Bypass-Tunnel-Reminder: true\r\n" .
                   "Accept: application/json\r\n"
    ]
]);

$result = file_get_contents($url, false, $context);

if ($result === FALSE) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to fetch data']);
} else {
    echo $result;
}
?>
