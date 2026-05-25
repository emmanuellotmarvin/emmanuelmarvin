<?php
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);

    // Retrieve and sanitize form inputs
    $name = isset($_POST['name']) ? htmlspecialchars($_POST['name']) : '';
    $email = isset($_POST['email']) ? filter_var($_POST['email'], FILTER_SANITIZE_EMAIL) : '';
    $phone = isset($_POST['phone']) ? htmlspecialchars($_POST['phone']) : '';
    $message = isset($_POST['message']) ? htmlspecialchars($_POST['message']) : '';
    $agree = isset($_POST['agree']) ? $_POST['agree'] : '';

    // Rate limiting to prevent spam
    session_start();
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $current_time = time();
    
    // Check for honeypot field (hidden field that bots might fill)
    if (!empty($_POST['website'])) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Spam detected.']);
        exit;
    }
    
    // IP-based rate limiting (max 10 emails per hour per IP - more lenient for testing)
    $rate_limit_file = sys_get_temp_dir() . '/portfolio_rate_limit_' . md5($client_ip) . '.txt';
    $max_emails_per_hour = 10;
    $hour_in_seconds = 3600;
    
    // Try-catch for file operations to prevent 409 conflicts
    try {
        if (file_exists($rate_limit_file)) {
            $rate_data = json_decode(file_get_contents($rate_limit_file), true);
            $rate_data = $rate_data ?: ['count' => 0, 'first_request' => $current_time];
            
            // Reset counter if more than an hour has passed
            if ($current_time - $rate_data['first_request'] > $hour_in_seconds) {
                $rate_data = ['count' => 0, 'first_request' => $current_time];
            }
            
            // Check if limit exceeded
            if ($rate_data['count'] >= $max_emails_per_hour) {
                http_response_code(429);
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Rate limit exceeded. Please try again later.']);
                exit;
            }
        } else {
            $rate_data = ['count' => 0, 'first_request' => $current_time];
        }
    } catch (Exception $e) {
        // If file operations fail, skip rate limiting to prevent 409 errors
        $rate_data = ['count' => 0, 'first_request' => $current_time];
        error_log("Rate limiting file error: " . $e->getMessage());
    }
    
    // Session-based rate limiting (max 1 email per 2 minutes per session - reduced for testing)
    if (isset($_SESSION['last_email_time']) && ($current_time - $_SESSION['last_email_time']) < 120) {
        http_response_code(429);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Please wait at least 2 minutes between submissions.']);
        exit;
    }

    // Validate required fields
    if (empty($name) || empty($email) || empty($message) || empty($agree)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Please fill in all required fields and agree to the Terms & Conditions.']);
        exit;
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Please provide a valid email address.']);
        exit;
    }

    // Email settings
    $to = "emmanuel.lot.marvin@gmail.com"; // CHANGE THIS TO YOUR EMAIL
    $subject = "Message from your portfolio" . (isset($_POST['subject']) ? " - " . htmlspecialchars($_POST['subject']) : "");
    // Secure headers to prevent injection
    $from_email = filter_var($email, FILTER_VALIDATE_EMAIL) ? $email : 'noreply@yourdomain.com';
    $headers = "From: Portfolio Contact <noreply@emmanuelmarvin.com>\r\n" .
               "Reply-To: " . $from_email . "\r\n" .
               "X-Mailer: PHP/" . phpversion() . "\r\n" .
               "Content-Type: text/plain; charset=UTF-8\r\n";

    // Construct email body
    $body = "You have a new message from your portfolio\n\n";
    $body .= "Name: " . $name . "\n";
    $body .= "Email: " . $email . "\n";
    $body .= "Phone: " . $phone . "\n";
    $body .= "Message: " . $message . "\n";

    // Send email
    $send = mail($to, $subject, $body, $headers);

    // Provide feedback
    if ($send) {
        // Update rate limiting counters after successful send
        try {
            $rate_data['count']++;
            file_put_contents($rate_limit_file, json_encode($rate_data), LOCK_EX);
            $_SESSION['last_email_time'] = $current_time;
        } catch (Exception $e) {
            error_log("Rate limiting update error: " . $e->getMessage());
        }
        
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'message' => 'Email sent successfully!']);
    } else {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Failed to send email. Please try again later.']);
        error_log("Failed to send email. From: $email, To: $to, Subject: $subject");
    }
?>
