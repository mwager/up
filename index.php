<?php
/**
 * `up.php` is a minimal, single-file, zero-knowledge secure transfer tool written in PHP and JavaScript.
 *
 * It allows two parties to securely transfer text or files using client-side encryption, without the server ever seeing plaintext.
 */
// ---------------- SECURITY HEADERS ----------------
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Referrer-Policy: no-referrer");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");

ini_set('display_errors', 0);
error_reporting(0);

// ---------------- CONFIG ----------------
define("TTL_SECONDS", 60);
$storageDir = __DIR__ . "/_storage/";
@mkdir($storageDir, 0700, true);

// ---------------- TOKEN VALIDATION ----------------
$token = $_GET['p'] ?? '';
if (!preg_match('/^[A-Za-z]{32}$/', $token)) {
    http_response_code(400);
    exit("Invalid or missing token.");
}

$filePath = $storageDir . hash('sha256', $token) . ".json";

// ---------------- HANDLE UPLOAD ----------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents("php://input"), true);
    if (!isset($input['iv'], $input['ct'])) {
        http_response_code(400);
        exit;
    }

    $payload = [
        "iv" => $input['iv'],
        "ct" => $input['ct'],
        "created" => time()
    ];

    file_put_contents($filePath, json_encode($payload), LOCK_EX);
    exit("OK");
}

// ---------------- HANDLE DOWNLOAD ----------------
if (isset($_GET['get'])) {
    if (!file_exists($filePath)) {
        http_response_code(404);
        exit;
    }

    $data = json_decode(file_get_contents($filePath), true);
    if (!$data || time() - $data['created'] > TTL_SECONDS) {
        @unlink($filePath);
        http_response_code(410);
        exit;
    }

    @unlink($filePath); // single-use delete
    header("Content-Type: application/json");
    echo json_encode(["iv" => $data['iv'], "ct" => $data['ct']]);
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Secure Transfer</title>
<style>
body { font-family: Arial; margin: 40px; }
textarea { width: 100%; height: 200px; }
button { padding: 10px 20px; margin-top: 10px; }
</style>
</head>
<body>
<h2>Secure 60s Transfer</h2>

<textarea id="textInput" placeholder="Paste text here..."></textarea>
<br>
<input type="file" id="fileInput">
<br>
<button onclick="upload()">Encrypt & Upload</button>
<button onclick="downloadData()">Download & Decrypt</button>

<script>
const params = new URLSearchParams(location.search);
const token = params.get("p");

async function deriveKey(token) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(token),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode("mwager-up-salt"),
            iterations: 150000,
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptBuffer(key, buffer) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        buffer
    );

    return {
        iv: btoa(String.fromCharCode(...iv)),
        ct: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
    };
}

async function upload() {
    if (!token) {
        alert("Missing token in URL.");
        return;
    }

    const key = await deriveKey(token);

    let buffer;
    const file = document.getElementById("fileInput").files[0];

    if (file) {
        buffer = await file.arrayBuffer();
    } else {
        const text = document.getElementById("textInput").value;
        buffer = new TextEncoder().encode(text);
    }

    const encrypted = await encryptBuffer(key, buffer);

    await fetch(location.pathname + location.search, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(encrypted)
    });

    alert("Uploaded. Expires in 60 seconds.");
}

async function downloadData() {
    if (!token) {
        alert("Missing token.");
        return;
    }

    const key = await deriveKey(token);
    const response = await fetch(location.pathname + location.search + "&get=1");

    if (!response.ok) {
        alert("Not available or expired.");
        return;
    }

    const data = await response.json();

    const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(data.ct), c => c.charCodeAt(0));

    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            ct
        );

        const blob = new Blob([decrypted]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "decrypted_output";
        a.click();
        URL.revokeObjectURL(url);

    } catch (e) {
        alert("Decryption failed.");
    }
}
</script>

</body>
</html>
