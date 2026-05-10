<?php
declare(strict_types=1);

/**
 * がんばりカレンダー 通知メール送信API
 * - 4層スパム対策: Origin/Referer + Honeypot + 共有トークン + レート制限
 * - 停止スイッチ: 同階層に kill-switch ファイルを置けば全リクエスト503
 */

// ========== 停止スイッチ ==========
if (file_exists(__DIR__ . '/kill-switch')) {
    http_response_code(503);
    exit;
}

// ========== 設定読み込み ==========
$configFile = __DIR__ . '/config.php';
if (!file_exists($configFile)) {
    http_response_code(500);
    error_log('[ganbari-calendar] config.php not found');
    exit;
}
$config = require $configFile;

// ========== CORS ==========
$allowedOrigin = $config['allowed_origin'] ?? '';
header('Access-Control-Allow-Origin: ' . $allowedOrigin);
header('Vary: Origin');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json; charset=utf-8');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'method']);
    exit;
}

// ========== 1層目: Origin/Refererチェック ==========
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$check = $origin ?: $referer;
if (!$check || strpos($check, $allowedOrigin) !== 0) {
    http_response_code(403);
    echo json_encode(['error' => 'origin']);
    exit;
}

// ========== ボディ取得 ==========
$raw = file_get_contents('php://input');
if ($raw === false || strlen($raw) > 8192) {
    http_response_code(413);
    exit;
}
$body = json_decode($raw, true);
if (!is_array($body)) {
    http_response_code(400);
    echo json_encode(['error' => 'json']);
    exit;
}

// ========== 2層目: Honeypot ==========
// HTMLには見えない hp フィールドを仕込んでおく。Botが自動入力したら拒否
if (!empty($body['hp'])) {
    http_response_code(204); // 成功風に返してBotに気付かせない
    exit;
}

// ========== type チェック ==========
if (($body['type'] ?? '') !== 'ganbari-calendar') {
    http_response_code(400);
    echo json_encode(['error' => 'type']);
    exit;
}

// ========== 3層目: 共有秘密トークン ==========
$token = (string)($body['token'] ?? '');
$expectedToken = $config['shared_token'] ?? '';
if ($expectedToken === '' || !hash_equals($expectedToken, $token)) {
    http_response_code(403);
    echo json_encode(['error' => 'token']);
    exit;
}

// ========== 必須項目検証 ==========
$to = trim((string)($body['to'] ?? ''));
$subject = trim((string)($body['subject'] ?? ''));
$bodyText = trim((string)($body['body'] ?? ''));

if ($to === '' || $subject === '' || $bodyText === '') {
    http_response_code(400);
    echo json_encode(['error' => 'fields']);
    exit;
}
if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['error' => 'email']);
    exit;
}
if (mb_strlen($subject) > 200 || mb_strlen($bodyText) > 4000) {
    http_response_code(413);
    echo json_encode(['error' => 'length']);
    exit;
}

// ========== 宛先ドメイン許可リスト（任意） ==========
if (!empty($config['allowed_domains']) && is_array($config['allowed_domains'])) {
    $domain = strtolower(substr($to, (int)strrpos($to, '@') + 1));
    if (!in_array($domain, $config['allowed_domains'], true)) {
        http_response_code(403);
        echo json_encode(['error' => 'domain']);
        exit;
    }
}

// ========== 4層目: レート制限 ==========
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$rlDir = __DIR__ . '/data/rate-limit';
if (!is_dir($rlDir)) {
    @mkdir($rlDir, 0755, true);
}

/**
 * @return bool true なら許可、false ならレート超過
 */
function rateLimitCheck(string $key, int $windowSec, int $maxCount, string $rlDir): bool {
    $file = $rlDir . '/' . hash('sha256', $key) . '.json';
    $now = time();
    $log = [];
    if (file_exists($file)) {
        $raw = @file_get_contents($file);
        if ($raw !== false) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $log = array_filter($decoded, fn($t) => is_int($t) && $t > $now - $windowSec);
            }
        }
    }
    if (count($log) >= $maxCount) {
        return false;
    }
    $log[] = $now;
    @file_put_contents($file, json_encode(array_values($log)), LOCK_EX);
    return true;
}

if (!rateLimitCheck('ip:' . $ip, 60, 1, $rlDir)) {
    http_response_code(429);
    echo json_encode(['error' => 'rate_ip']);
    exit;
}
if (!rateLimitCheck('mail:' . strtolower($to), 3600, 20, $rlDir)) {
    http_response_code(429);
    echo json_encode(['error' => 'rate_mail']);
    exit;
}

// ========== PHPMailer でメール送信 ==========
require __DIR__ . '/../vendor/autoload.php';

$mail = new PHPMailer\PHPMailer\PHPMailer(true);
try {
    $mail->isSMTP();
    $mail->Host       = $config['smtp']['host'];
    $mail->Port       = (int)$config['smtp']['port'];
    $mail->SMTPAuth   = true;
    $mail->Username   = $config['smtp']['user'];
    $mail->Password   = $config['smtp']['pass'];
    $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
    $mail->CharSet    = 'UTF-8';

    $mail->setFrom($config['smtp']['from'], $config['smtp']['from_name'] ?? 'がんばりカレンダー');
    $mail->addAddress($to);

    $mail->Subject = $subject;
    $mail->Body    = $bodyText;

    $mail->send();
    echo json_encode(['ok' => true]);
} catch (\Throwable $e) {
    http_response_code(500);
    error_log('[ganbari-calendar] mail send failed: ' . $e->getMessage());
    echo json_encode(['error' => 'send']);
}
