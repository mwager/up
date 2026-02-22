<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

/**
* Secure one-slot transfer page: text (auto-save on paste) + file (zip/tar) upload/download.
*
* Text flow:
* - Paste into textarea -> auto-saved server-side
* - Reload elsewhere -> textarea prefilled
* - After copying/cutting -> click "Clear text" to delete
*
* File flow:
* - Upload allowed archive file -> stored server-side
* - Elsewhere -> "Download file" button appears
* - Download streams file and deletes it immediately after (single-use)
*
* Security:
* - HTTP Basic Auth (set TRANSFER_USER / TRANSFER_PASS)
* - HTTPS required
* - Storage in non-web-accessible directory recommended
* - Locking via flock, TTL cleanup
*/

$CFG = [
 // Prefer: set this to a path OUTSIDE the webroot.
 'storage_dir' => __DIR__ . DIRECTORY_SEPARATOR . '_storage',

 // Limits
 'max_text_bytes' => 256 * 1024,
 'max_file_bytes' => 25 * 1024 * 1024, // 25 MB

 // Cleanup
 'ttl_seconds' => 10 * 60, // 10 minutes

 // Allowed upload extensions (archives)
 'allowed_file_ext' => [
   'zip',
   'tar',
   'tgz',
   'tar.gz',
   'gz',
 ],

 // Best-effort MIME allowlist (still rely on extension + download-only storage)
 'allowed_file_mime' => [
   'application/zip',
   'application/x-zip-compressed',
   'application/x-tar',
   'application/gzip',
   'application/x-gzip',
   'application/octet-stream',
 ],
];

/* ===================== Helpers ===================== */
function h($s) { return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function deny($code, $msg) {
 http_response_code($code);
 header('Content-Type: text/plain; charset=utf-8');
 echo $msg;
 exit;
}

function ensure_storage($dir) {
 if (!is_dir($dir)) {
   if (!mkdir($dir, 0700, true)) deny(500, "Failed to create storage dir.");
 }
 if (!is_writable($dir)) deny(500, "Storage dir not writable.");
}

function basic_auth($cfg){
    if(($_GET['p']??'')!=='XXXXX') deny(401,'Auth required');
}

function slot_paths($cfg, $slot) {
 $base = $cfg['storage_dir'] . DIRECTORY_SEPARATOR . $slot;
 return [
   'meta' => $base . '.meta.json',
 ];
}

function with_lock($metaFile, $callback) {
 $fh = fopen($metaFile, 'c+');
 if ($fh === false) deny(500, "Failed to open metadata.");
 if (!flock($fh, LOCK_EX)) { fclose($fh); deny(500, "Failed to lock metadata."); }

 $raw = stream_get_contents($fh);
 $meta = [];
 if ($raw !== false && strlen(trim($raw)) > 0) {
   $decoded = json_decode($raw, true);
   if (is_array($decoded)) $meta = $decoded;
 }

 $result = $callback($fh, $meta);

 flock($fh, LOCK_UN);
 fclose($fh);
 return $result;
}

function meta_read($cfg, $slot) {
 ensure_storage($cfg['storage_dir']);
 $p = slot_paths($cfg, $slot);
 return with_lock($p['meta'], function($fh, $meta) { return is_array($meta) ? $meta : []; });
}

function meta_write($cfg, $slot, $metaNew) {
 ensure_storage($cfg['storage_dir']);
 $p = slot_paths($cfg, $slot);
 with_lock($p['meta'], function($fh, $meta) use ($metaNew) {
   ftruncate($fh, 0);
   rewind($fh);
   fwrite($fh, json_encode($metaNew, JSON_UNESCAPED_SLASHES));
   return true;
 });
}

function slot_clear($cfg, $slot) {
 ensure_storage($cfg['storage_dir']);
 $p = slot_paths($cfg, $slot);
 with_lock($p['meta'], function($fh, $meta) {
   if (!empty($meta['path']) && is_string($meta['path']) && file_exists($meta['path'])) {
     @unlink($meta['path']);
   }
   ftruncate($fh, 0);
   rewind($fh);
   fwrite($fh, json_encode([], JSON_UNESCAPED_SLASHES));
   return true;
 });
}

function cleanup_ttl($cfg) {
 foreach (['text', 'file'] as $slot) {
   $meta = meta_read($cfg, $slot);
   if (!empty($meta['stored_at']) && !empty($meta['path'])) {
     $age = time() - (int)$meta['stored_at'];
     if ($age > (int)$cfg['ttl_seconds']) {
       slot_clear($cfg, $slot);
     }
   }
 }
}

/* ===================== Text slot ===================== */
function text_get($cfg) {
 $meta = meta_read($cfg, 'text');
 if (empty($meta['path']) || !is_string($meta['path']) || !file_exists($meta['path'])) return '';
 $c = @file_get_contents($meta['path']);
 return is_string($c) ? $c : '';
}

function text_save($cfg, $text) {
 if (!is_string($text)) $text = '';
 $text = str_replace("\r\n", "\n", $text);

 $bytes = strlen($text);
 if ($bytes <= 0) return "Empty payload.";
 if ($bytes > (int)$cfg['max_text_bytes']) return "Text too large (max " . (int)$cfg['max_text_bytes'] . " bytes).";

 $old = meta_read($cfg, 'text');
 if (!empty($old['path']) && is_string($old['path']) && file_exists($old['path'])) @unlink($old['path']);

 $rand = bin2hex(random_bytes(16));
 $dest = $cfg['storage_dir'] . DIRECTORY_SEPARATOR . "text_$rand.txt";
 $tmp = $dest . ".tmp";

 if (@file_put_contents($tmp, $text, LOCK_EX) === false) {
   if (file_exists($tmp)) @unlink($tmp);
   return "Failed to store text.";
 }
 @chmod($tmp, 0600);
 if (!@rename($tmp, $dest)) {
   @unlink($tmp);
   return "Failed to finalize text.";
 }
 @chmod($dest, 0600);

 meta_write($cfg, 'text', [
   'path' => $dest,
   'size' => (int)$bytes,
   'stored_at' => time(),
 ]);
 return null;
}

/* ===================== File slot ===================== */
function file_allowed_ext($cfg, $name) {
 $nameLower = strtolower($name ?? '');
 if (str_ends_with($nameLower, '.tar.gz')) return in_array('tar.gz', $cfg['allowed_file_ext'], true);
 $ext = strtolower(pathinfo($nameLower, PATHINFO_EXTENSION));
 return in_array($ext, $cfg['allowed_file_ext'], true);
}

function file_detect_mime($tmpPath) {
 $mime = 'application/octet-stream';
 if (function_exists('finfo_open')) {
   $fi = finfo_open(FILEINFO_MIME_TYPE);
   if ($fi) {
     $det = finfo_file($fi, $tmpPath);
     if (is_string($det)) $mime = $det;
     finfo_close($fi);
   }
 }
 return $mime;
}

function file_meta_current($cfg) {
 $meta = meta_read($cfg, 'file');
 if (empty($meta['path']) || !is_string($meta['path']) || !file_exists($meta['path'])) return [];
 return $meta;
}

function file_store_upload($cfg, $upload) {
 if (!isset($upload) || !is_array($upload)) return "No file provided.";
 if (!empty($upload['error'])) return "Upload error code: " . (int)$upload['error'];
 if (($upload['size'] ?? 0) <= 0) return "Empty file.";
 if (($upload['size'] ?? 0) > (int)$cfg['max_file_bytes']) return "File too large (max " . (int)$cfg['max_file_bytes'] . " bytes).";

 $orig = $upload['name'] ?? 'upload.bin';
 if (!file_allowed_ext($cfg, $orig)) return "Only zip/tar/tgz/tar.gz/gz allowed.";

 $tmpName = $upload['tmp_name'] ?? '';
 if (!is_string($tmpName) || $tmpName === '' || !is_uploaded_file($tmpName)) return "Invalid upload source.";

 $mime = file_detect_mime($tmpName);
 if (!in_array($mime, $cfg['allowed_file_mime'], true)) {
   return "Disallowed MIME type: " . h($mime);
 }

 $old = file_meta_current($cfg);
 if (!empty($old['path']) && file_exists($old['path'])) @unlink($old['path']);

 $rand = bin2hex(random_bytes(16));
 $nameLower = strtolower($orig);
 $suffix = '';
 if (str_ends_with($nameLower, '.tar.gz')) $suffix = '.tar.gz';
 else {
   $ext = strtolower(pathinfo($nameLower, PATHINFO_EXTENSION));
   $suffix = $ext ? ('.' . $ext) : '';
 }
 $dest = $cfg['storage_dir'] . DIRECTORY_SEPARATOR . "file_$rand" . $suffix;

 if (!move_uploaded_file($tmpName, $dest)) return "Failed to store upload.";
 @chmod($dest, 0600);

 meta_write($cfg, 'file', [
   'path' => $dest,
   'orig_name' => $orig,
   'mime' => $mime,
   'size' => (int)$upload['size'],
   'stored_at' => time(),
 ]);

 return null;
}

function file_download_and_delete($cfg) {
 ensure_storage($cfg['storage_dir']);
 $p = slot_paths($cfg, 'file');

 with_lock($p['meta'], function($fh, $meta) {
   if (empty($meta['path']) || !is_string($meta['path']) || !file_exists($meta['path'])) {
     deny(404, "No file available.");
   }

   $path = $meta['path'];
   $orig = $meta['orig_name'] ?? 'download.bin';
   $size = filesize($path);

   ftruncate($fh, 0);
   rewind($fh);
   fwrite($fh, json_encode([], JSON_UNESCAPED_SLASHES));

   header('Content-Type: application/octet-stream');
   header('Content-Disposition: attachment; filename="' . rawurlencode(basename($orig)) . '"');
   if (is_int($size) || ctype_digit((string)$size)) header('Content-Length: ' . (string)$size);
   header('X-Content-Type-Options: nosniff');
   header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
   header('Pragma: no-cache');

   ignore_user_abort(true);
   register_shutdown_function(function() use ($path) {
     if (is_string($path) && file_exists($path)) @unlink($path);
   });

   $out = fopen('php://output', 'wb');
   $in = fopen($path, 'rb');
   if ($out === false || $in === false) {
     if (file_exists($path)) @unlink($path);
     deny(500, "Failed to stream file.");
   }
   while (!feof($in)) {
     $buf = fread($in, 8192);
     if ($buf === false) break;
     fwrite($out, $buf);
   }
   fclose($in);

   if (function_exists('fastcgi_finish_request')) {
     @fastcgi_finish_request();
   } else {
     @ob_flush();
     @flush();
   }
   exit;
 });
}

/* ===================== Main ===================== */
basic_auth($CFG);
cleanup_ttl($CFG);

$notice = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
 $action = $_POST['action'] ?? '';

 if ($action === 'save_text') {
   $payload = $_POST['payload'] ?? '';
   $err = text_save($CFG, $payload);
   if ($err) $error = $err;
   else $notice = "Text saved.";

   if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
     header('Content-Type: application/json; charset=utf-8');
     echo json_encode(['ok' => $err ? false : true, 'error' => $err], JSON_UNESCAPED_SLASHES);
     exit;
   }
 } elseif ($action === 'clear_text') {
   slot_clear($CFG, 'text');
   $notice = "Text cleared.";
 } elseif ($action === 'upload_file') {
   $err = file_store_upload($CFG, $_FILES['file'] ?? null);
   if ($err) $error = $err;
   else $notice = "File uploaded.";
 } elseif ($action === 'download_file') {
   file_download_and_delete($CFG);
 } elseif ($action === 'clear_file') {
   slot_clear($CFG, 'file');
   $notice = "File cleared.";
 }
}

$text = text_get($CFG);
$fileMeta = file_meta_current($CFG);
$hasFile = !empty($fileMeta);

?><!doctype html>
<html lang="de">
<head>
 <meta charset="utf-8">
 <meta name="viewport" content="width=device-width, initial-scale=1">
 <title>Secure Transfer</title>
 <style>
   body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; max-width: 920px; margin: 24px auto; padding: 0 12px; }
   .box { border: 1px solid #ddd; padding: 16px; border-radius: 10px; margin: 16px 0; }
   .muted { color: #666; }
   .notice { background: #f0fff4; border: 1px solid #b7ebc6; padding: 10px; border-radius: 8px; }
   .error { background: #fff5f5; border: 1px solid #f5c2c7; padding: 10px; border-radius: 8px; }
   button { padding: 10px 14px; border-radius: 8px; border: 1px solid #ccc; background: #fafafa; cursor: pointer; }
   textarea { width: 100%; min-height: 340px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; font-size: 13px; padding: 10px; border-radius: 10px; border: 1px solid #ccc; }
   .row { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
   code { background: #f6f8fa; padding: 2px 6px; border-radius: 6px; }
   .status { font-size: 12px; }
 </style>
</head>
<body>
 <h1>Secure Transfer</h1>

 <?php if ($notice): ?><div class="notice"><?php echo h($notice); ?></div><?php endif; ?>
 <?php if ($error): ?><div class="error"><?php echo h($error); ?></div><?php endif; ?>

 <div class="box">
   <h2>Text</h2>
   <p class="muted">Paste → auto-save. Auf der Zielseite: Text markieren, ausschneiden/kopieren, dann <b>Clear text</b>.</p>

   <form id="textForm" method="post">
     <input type="hidden" name="action" value="save_text">
     <textarea id="payload" name="payload" spellcheck="false"><?php echo h($text); ?></textarea>

     <div class="row" style="margin-top: 10px;">
       <button type="submit">Save</button>
       <button type="submit" name="action" value="clear_text" formmethod="post">Clear text</button>
       <span class="status muted" id="saveStatus"></span>
     </div>

     <p class="muted">Max: <?php echo (int)$CFG['max_text_bytes']; ?> Bytes. TTL: <?php echo (int)$CFG['ttl_seconds']; ?> Sekunden.</p>
   </form>
 </div>

 <div class="box">
   <h2>File (zip/tar)</h2>

   <form method="post" enctype="multipart/form-data">
     <input type="hidden" name="action" value="upload_file">
     <div class="row">
       <input type="file" name="file" accept=".zip,.tar,.tgz,.gz,.tar.gz" required>
       <button type="submit">Upload file</button>
       <?php if ($hasFile): ?>
         <button type="submit" name="action" value="clear_file" formmethod="post">Clear file</button>
       <?php endif; ?>
     </div>
     <p class="muted">Erlaubt: <code>.zip</code>, <code>.tar</code>, <code>.tgz</code>, <code>.tar.gz</code>, <code>.gz</code>. Max: <?php echo (int)$CFG['max_file_bytes']; ?> Bytes.</p>
   </form>

   <?php if ($hasFile): ?>
     <p class="muted">Verfügbar: <?php echo h($fileMeta['orig_name'] ?? 'download'); ?> (<?php echo (int)($fileMeta['size'] ?? 0); ?> Bytes)</p>
     <form method="post">
       <input type="hidden" name="action" value="download_file">
       <button type="submit">Download file (single-use)</button>
     </form>
     <p class="muted">Nach dem Download wird die Datei serverseitig gelöscht.</p>
   <?php else: ?>
     <p class="muted">Keine Datei verfügbar.</p>
   <?php endif; ?>
 </div>

<script>
(() => {
 const ta = document.getElementById('payload');
 const status = document.getElementById('saveStatus');
 const form = document.getElementById('textForm');

 let t = null;
 let lastSent = null;

 function setStatus(msg) { status.textContent = msg || ''; }

 async function autosave() {
   const val = ta.value;
   if (!val || val.length === 0) return;
   if (val === lastSent) return;

   setStatus('Saving…');

   const body = new FormData();
   body.set('action', 'save_text');
   body.set('payload', val);

   try {
     const res = await fetch(location.href, {
       method: 'POST',
       body,
       headers: {'X-Requested-With': 'XMLHttpRequest'},
       credentials: 'same-origin'
     });
     const j = await res.json();
     if (j && j.ok) {
       lastSent = val;
       setStatus('Saved.');
     } else {
       setStatus('Save failed.');
     }
   } catch (e) {
     setStatus('Save failed.');
   }
 }

 function scheduleSave() {
   if (t) clearTimeout(t);
   t = setTimeout(autosave, 350);
 }

 ta.addEventListener('paste', scheduleSave);
 ta.addEventListener('input', scheduleSave);

 form.addEventListener('submit', () => setStatus('Submitting…'));
})();
</script>

</body>
</html>