<?php

declare(strict_types=1);

/**
 * Carruthers Law -- static site intake endpoint.
 *
 * Plain PHP 8.4. No framework, no Composer. Receives the POST from the two
 * frozen WordPress forms (the Elementor contact form on /contact/ and the
 * lead form on /request-appointment/), runs anti-spam + validation, verifies
 * reCAPTCHA v2, always logs the lead to a CSV, then relays it by email via
 * the Mailgun HTTP API (plain curl, no SDK).
 * Success redirect = /contact/thank-you/.
 *
 * Config lives OUTSIDE the git repo and OUTSIDE the webroot, at
 * <vhost-root>/private/intake-config.php -- see intake-config.example.php
 * for the shape. Never fetched over HTTP.
 *
 * Static-site form handler: Carruthers field set (first + last name, two forms).
 */

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

function intake_redirect(string $path): never
{
    header('Location: ' . $path, true, 302);
    exit;
}

function intake_clean_header_value(string $value): string
{
    return trim(str_replace(["\r", "\n"], '', $value));
}

function intake_client_ip(array $cfg): string
{
    $header = $cfg['TRUSTED_PROXY_HEADER'] ?? null;
    if (is_string($header) && $header !== '' && !empty($_SERVER[$header])) {
        $first = trim(explode(',', (string) $_SERVER[$header])[0]);
        if (filter_var($first, FILTER_VALIDATE_IP)) {
            return $first;
        }
    }
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

/** File-based per-IP rate limit; fails OPEN on filesystem errors. */
function intake_rate_limited(string $dir, string $ip, int $limit, int $windowSecs): bool
{
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        error_log('[intake] could not create rate-limit dir: ' . $dir);
        return false;
    }
    $safeIp = preg_replace('/[^a-zA-Z0-9.:_-]/', '_', $ip) ?? 'unknown';
    $file = $dir . '/' . $safeIp . '.txt';
    $fh = fopen($file, 'c+');
    if ($fh === false) {
        error_log('[intake] could not open rate-limit file: ' . $file);
        return false;
    }
    $limited = false;
    if (flock($fh, LOCK_EX)) {
        $now = time();
        $raw = stream_get_contents($fh);
        $hits = array_filter(
            array_map('intval', array_filter(explode("\n", (string) $raw), 'strlen')),
            static fn (int $t): bool => $t > $now - $windowSecs
        );
        $hits[] = $now;
        $limited = count($hits) > $limit;
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, implode("\n", $hits));
        fflush($fh);
        flock($fh, LOCK_UN);
    }
    fclose($fh);
    return $limited;
}

function intake_verify_recaptcha(string $secret, string $token, string $ip): bool
{
    if ($secret === '' || $token === '') {
        error_log('[intake] reCAPTCHA: ' . ($secret === '' ? 'secret not configured' : 'no token in POST'));
        return false;
    }
    $ch = curl_init('https://www.google.com/recaptcha/api/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query(['secret' => $secret, 'response' => $token, 'remoteip' => $ip]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 8,
        CURLOPT_CONNECTTIMEOUT => 8,
    ]);
    $body = curl_exec($ch);
    $curlErr = curl_error($ch);
    curl_close($ch);
    if ($body === false) {
        error_log('[intake] reCAPTCHA request failed: ' . $curlErr);
        return false;
    }
    $data = json_decode((string) $body, true);
    if (!is_array($data) || empty($data['success'])) {
        $codes = is_array($data) && isset($data['error-codes']) ? implode(',', (array) $data['error-codes']) : 'unparseable';
        error_log('[intake] reCAPTCHA rejected: ' . $codes);
        return false;
    }
    return true;
}

function intake_append_csv(string $dir, array $row): void
{
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        error_log('[intake] could not create leads dir: ' . $dir);
        return;
    }
    $file = $dir . '/leads-' . gmdate('Y-m') . '.csv';
    $isNew = !file_exists($file);
    $fh = fopen($file, 'a');
    if ($fh === false) {
        error_log('[intake] could not open leads file: ' . $file);
        return;
    }
    if (flock($fh, LOCK_EX)) {
        if ($isNew) {
            fputcsv($fh, ['timestamp_utc', 'ip', 'form', 'name', 'last_name', 'email', 'phone', 'message', 'mailgun_status', 'mailgun_id'], ',', '"', '\\');
        }
        fputcsv($fh, $row, ',', '"', '\\');
        fflush($fh);
        flock($fh, LOCK_UN);
    }
    fclose($fh);
}

function intake_send_mailgun(array $cfg, array $f, string $ip, string $ua): array
{
    $url = rtrim((string) $cfg['MAILGUN_API_BASE'], '/') . '/' . $cfg['MAILGUN_DOMAIN'] . '/messages';
    $text = "New website inquiry from carrutherslaw.ca ({$f['form']} form).\n\n"
        . "Name: {$f['name']} {$f['last_name']}\n"
        . "Email: {$f['email']}\n"
        . "Phone: {$f['phone']}\n\n"
        . "Message:\n{$f['message']}\n\n"
        . "Submitted (UTC): " . gmdate('Y-m-d H:i:s') . "\n"
        . "IP: {$ip}\n"
        . "User agent: {$ua}\n";

    $post = [
        'from' => $cfg['MAIL_FROM'],
        'to' => implode(',', (array) $cfg['MAIL_TO']),
        'subject' => $cfg['MAIL_SUBJECT'] . ' (' . $f['form'] . ')',
        'text' => $text,
        'h:Reply-To' => intake_clean_header_value($f['email']),
    ];
    if (!empty($cfg['MAIL_BCC'])) {
        $post['bcc'] = implode(',', (array) $cfg['MAIL_BCC']);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_USERPWD => 'api:' . $cfg['MAILGUN_SENDING_KEY'],
        CURLOPT_POSTFIELDS => $post,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 15,
    ]);
    $body = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        error_log('[intake] Mailgun request failed: ' . $curlErr);
        return ['ok' => false, 'status' => 'curl_error', 'id' => ''];
    }
    $data = json_decode((string) $body, true);
    if ($httpCode >= 200 && $httpCode < 300 && is_array($data) && !empty($data['id'])) {
        return ['ok' => true, 'status' => 'sent', 'id' => (string) $data['id']];
    }
    error_log('[intake] Mailgun send failed (HTTP ' . $httpCode . '): ' . substr((string) $body, 0, 500));
    return ['ok' => false, 'status' => 'http_' . $httpCode, 'id' => ''];
}

// 0) Load config -- <vhost-root>/private/intake-config.php, sibling of the
//    deploy dir and httpdocs, outside the webroot.
$vhostRoot = dirname(__DIR__, 3);
$envConfig = getenv('INTAKE_CONFIG');
$configPath = ($envConfig !== false && $envConfig !== '') ? $envConfig : $vhostRoot . '/private/intake-config.php';

// Which form posted, and where to send the visitor back on error. Only the
// two known forms are accepted; anything else is treated as the contact form.
$formId = (string) ($_POST['form'] ?? 'contact');
$returnPaths = ['contact' => '/contact/', 'request-appointment' => '/request-appointment/'];
if (!isset($returnPaths[$formId])) {
    $formId = 'contact';
}
$returnPath = $returnPaths[$formId];
$successPath = '/contact/thank-you/';

if (!is_readable($configPath)) {
    error_log('[intake] config not readable: ' . $configPath);
    intake_redirect($returnPath . '?error=send');
}
$loadedCfg = require $configPath;

$defaults = [
    'MAILGUN_API_BASE' => 'https://api.mailgun.net/v3',
    'MAILGUN_DOMAIN' => 'mg.carrutherslaw.ca',
    'MAILGUN_SENDING_KEY' => '',
    'MAIL_TO' => [],
    'MAIL_BCC' => [],
    'MAIL_FROM' => 'Carruthers Law Website <website@carrutherslaw.ca>',
    'MAIL_SUBJECT' => 'Website inquiry',
    'RECAPTCHA_SECRET' => '',
    'LEADS_DIR' => $vhostRoot . '/private/leads',
    'RATE_DIR' => $vhostRoot . '/private/ratelimit',
    'RATE_LIMIT' => 5,
    'RATE_WINDOW' => 600,
    'DRY_RUN' => false,
    'TRUSTED_PROXY_HEADER' => null,
];
$cfg = is_array($loadedCfg) ? $loadedCfg : [];
foreach ($defaults as $key => $default) {
    if (!array_key_exists($key, $cfg) || $cfg[$key] === null || $cfg[$key] === '') {
        $cfg[$key] = $default;
    }
}

// 1) Method
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    intake_redirect($returnPath);
}

$ip = intake_client_ip($cfg);
$userAgent = intake_clean_header_value((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));

// 2) Honeypot + time-trap. Bots get a fake success, never a hint they were
//    caught. Even spam-classified posts are logged (status spam_*), never
//    emailed -- so a false positive is never silently lost, but it never
//    reaches an inbox either.
$spamReason = '';
$honeypot = trim((string) ($_POST['ref2'] ?? ''));
if ($honeypot !== '') {
    $spamReason = 'spam_honeypot';
}

$submittedAtMs = (int) ($_POST['_ts'] ?? 0);
$ageMs = (int) (microtime(true) * 1000) - $submittedAtMs;
if ($spamReason === '' && $submittedAtMs > 0 && $ageMs >= 0 && $ageMs < 3000) {
    $spamReason = 'spam_timetrap';
}

if ($spamReason !== '') {
    $cut = static fn (string $k, int $n): string => mb_substr(trim((string) ($_POST[$k] ?? '')), 0, $n);
    intake_append_csv((string) $cfg['LEADS_DIR'], [
        gmdate('Y-m-d\TH:i:s\Z'), $ip, $formId,
        $cut('name', 200), $cut('last_name', 200), $cut('email', 200), $cut('phone', 40), $cut('message', 5000),
        $spamReason, '',
    ]);
    intake_redirect($successPath);
}

// 3) Rate limit
if (intake_rate_limited((string) $cfg['RATE_DIR'], $ip, (int) $cfg['RATE_LIMIT'], (int) $cfg['RATE_WINDOW'])) {
    intake_redirect($returnPath . '?error=send');
}

// 4) Validate fields (matches the two forms' markup). Last name and phone
//    are optional on the contact form, as they were on the live site.
$fields = [
    'form' => $formId,
    'name' => intake_clean_header_value((string) ($_POST['name'] ?? '')),
    'last_name' => intake_clean_header_value((string) ($_POST['last_name'] ?? '')),
    'email' => intake_clean_header_value((string) ($_POST['email'] ?? '')),
    'phone' => intake_clean_header_value((string) ($_POST['phone'] ?? '')),
    'message' => trim(str_replace("\r\n", "\n", (string) ($_POST['message'] ?? ''))),
];

$valid = mb_strlen($fields['name']) >= 1 && mb_strlen($fields['name']) <= 200
    && mb_strlen($fields['last_name']) <= 200
    && filter_var($fields['email'], FILTER_VALIDATE_EMAIL) !== false
    && mb_strlen($fields['phone']) <= 40
    && mb_strlen($fields['message']) >= 1 && mb_strlen($fields['message']) <= 5000;

if (!$valid) {
    intake_redirect($returnPath . '?error=fields');
}

// 5) reCAPTCHA v2 (skipped only in DRY_RUN)
if (!$cfg['DRY_RUN']) {
    $recaptchaToken = (string) ($_POST['g-recaptcha-response'] ?? '');
    if (!intake_verify_recaptcha((string) $cfg['RECAPTCHA_SECRET'], $recaptchaToken, $ip)) {
        intake_redirect($returnPath . '?error=captcha');
    }
}

// 6) Send via Mailgun, then log the CSV row once, always with its outcome.
if ($cfg['DRY_RUN']) {
    $sendResult = ['ok' => true, 'status' => 'dry_run', 'id' => ''];
} else {
    $sendResult = intake_send_mailgun($cfg, $fields, $ip, $userAgent);
}

intake_append_csv((string) $cfg['LEADS_DIR'], [
    gmdate('Y-m-d\TH:i:s\Z'), $ip, $formId,
    $fields['name'], $fields['last_name'], $fields['email'], $fields['phone'], $fields['message'],
    $sendResult['status'], $sendResult['id'],
]);

if (!$sendResult['ok']) {
    intake_redirect($returnPath . '?error=send');
}

// 7) Success
intake_redirect($successPath);
